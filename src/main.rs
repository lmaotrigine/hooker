// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::config::Config;
use axum::{
    body::Bytes,
    extract::{FromRequestParts, State},
    http::{request::Parts, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    RequestExt, Router, Server,
};
use axum_realip::RealIp;
use color_eyre::eyre::Context;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::{borrow::Cow, net::SocketAddr, str::FromStr};
use tokio::process::Command;
use tracing::{error, warn};

mod config;

type Error = (StatusCode, Cow<'static, str>);

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
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let config = Config::try_new().wrap_err("Failed to load config")?;
    let router = Router::new()
        .route("/.well-known/deploy", post(deploy))
        .layer(middleware::from_fn(handle_errors_middleware))
        .with_state(config.clone());
    let signal = async {
        let _ = tokio::signal::ctrl_c().await;
        warn!("Initiating graceful shutdown");
    };
    let server = Server::bind(&config.bind())
        .serve(router.into_make_service_with_connect_info::<SocketAddr>());
    eprintln!("Listening on {}", server.local_addr());
    server.with_graceful_shutdown(signal).await?;
    Ok(())
}

async fn handle_errors_middleware<B: Send + std::fmt::Debug + 'static>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, Error> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let ip = match req.extract_parts::<RealIp>().await {
        Ok(RealIp(ip)) => ip,
        Err(e) => {
            error!("Failed to get real IP from request: {e:?}\n{req:#?}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".into(),
            ));
        }
    };
    let headers = req.headers().clone();
    let resp = next.run(req).await;
    let status = resp.status();
    if status == StatusCode::OK {
        Ok(resp)
    } else {
        let code = status.as_u16();
        warn!("Returned {code} to {ip} - tried to {method} {path} with headers {headers:?}");
        Err((status, status.canonical_reason().unwrap_or_default().into()))
    }
}

async fn deploy(
    State(config): State<Config>,
    request_secret: Secret,
    body: Bytes,
) -> Result<(), Error> {
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
        let cmd = Command::new("docker")
            .args([
                "compose",
                "-f",
                config.compose_file().to_str().unwrap(),
                "up",
                "-d",
            ])
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
    }
    Ok(())
}
