// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::config::Config;
use axum::{
    body::Bytes,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::post,
    Extension, Router, Server,
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::Value;
use sha2::Sha256;
use std::{borrow::Cow, str::FromStr};
use tokio::process::Command;

mod config;

struct Secret(String);

impl Secret {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    fn value(&self) -> &str {
        &self.0
    }
}

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Secret {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get("X-Hub-Signature-256")
            .ok_or((StatusCode::UNAUTHORIZED, "Missing signature"))?
            .as_bytes();
        std::str::from_utf8(raw)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF-8"))?
            .trim()
            .strip_prefix("sha256=")
            .ok_or((StatusCode::BAD_REQUEST, "Malformed signature"))
            .map(Self::new)
    }
}

trait MacExt {
    fn with_data(self, data: &[u8]) -> Self;
}

impl<M: Mac> MacExt for M {
    fn with_data(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

struct HexEncoder<'a> {
    bytes: core::slice::Iter<'a, u8>,
    next: Option<char>,
}

impl<'a> HexEncoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: bytes.iter(),
            next: None,
        }
    }
}

impl<'a> Iterator for HexEncoder<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next.take() {
            Some(current) => Some(current),
            None => self.bytes.next().map(|byte| {
                let current = HEX_CHARS[(byte >> 4) as usize] as char;
                self.next = Some(HEX_CHARS[(byte & 0xf) as usize] as char);
                current
            }),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl<'a> ExactSizeIterator for HexEncoder<'a> {
    fn len(&self) -> usize {
        let mut length = self.bytes.len() * 2;
        if self.next.is_some() {
            length += 1;
        }
        length
    }
}

trait ToHex {
    fn encode_hex<T: FromIterator<char>>(&self) -> T;
}

impl<T: AsRef<[u8]>> ToHex for T {
    #[inline]
    fn encode_hex<U: FromIterator<char>>(&self) -> U {
        HexEncoder::new(self.as_ref()).collect()
    }
}

#[tokio::main]
async fn main() {
    let config = Config::try_new().expect("Failed to load config");
    let router = Router::new()
        .route("/.well-known/deploy", post(deploy))
        .layer(Extension(reqwest::Client::new()))
        .with_state(config.clone());
    let signal = async {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("Initiating graceful shutdown");
    };
    let server = Server::bind(&config.bind()).serve(router.into_make_service());
    eprintln!("Listening on {}", server.local_addr());
    server.with_graceful_shutdown(signal).await.unwrap();
}

async fn deploy(
    State(config): State<Config>,
    Extension(client): Extension<Client>,
    request_secret: Secret,
    body: Bytes,
) -> Result<(), (StatusCode, Cow<'static, str>)> {
    let secret = config
        .secret()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "No secret configured".into(),
        ))?
        .as_bytes();
    let sha = Hmac::<Sha256>::new_from_slice(secret)
        .unwrap()
        .with_data(body.as_ref())
        .finalize()
        .into_bytes()
        .encode_hex::<String>();
    if sha != request_secret.value() {
        return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
    }
    let raw = String::from_utf8_lossy(body.as_ref());
    let payload = Value::from_str(&raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid JSON in request body".into(),
        )
    })?;
    if payload["action"] == "completed"
        && payload["workflow_run"]["name"] == ".github/workflows/docker.yml"
    {
        let repo = payload["repository"]["full_name"].as_str().unwrap();
        let cmd = Command::new("docker")
            .args(["pull", &format!("ghcr.io/{repo}:latest")])
            .output()
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to run docker pull".into(),
                )
            })?;
        if !cmd.status.success() {
            let stderr = String::from_utf8_lossy(&cmd.stderr);
            eprintln!("docker pull failed: {stderr}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("docker pull failed: {stderr}").into(),
            ));
        }
        let resp = client
            .post(config.forward_to())
            .header("X-Hub-Signature-256", &format!("sha256={sha}"))
            .body(body)
            .send()
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Failed to forward request.".into()))?;
        return Err((
            resp.status(),
            resp.text()
                .await
                .map_err(|e| {
                    eprintln!("Got malformed/non-text response from downstream: {e:?}");
                    (
                        StatusCode::BAD_GATEWAY,
                        "Failed to read response body".into(),
                    )
                })?
                .into(),
        ));
    }
    Ok(())
}
