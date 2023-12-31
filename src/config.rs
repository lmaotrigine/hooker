// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use std::{fmt::Display, fs::read_to_string, net::SocketAddr, path::PathBuf};

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    bind: SocketAddr,
    compose_file: PathBuf,
    secret: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    TomlDe(toml::de::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlDe(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::TomlDe(e) => write!(f, "TOML deserialization error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::TomlDe(e) => Some(e),
        }
    }
}

impl Config {
    pub fn try_new() -> Result<Self, Error> {
        let file = read_to_string("config.toml")?;
        let config: Self = toml::from_str(&file)?;
        Ok(config)
    }

    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub const fn compose_file(&self) -> &PathBuf {
        &self.compose_file
    }
}
