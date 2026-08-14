use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use codex_tunnel::MAX_CONCURRENT_CONNECTIONS;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub listen: ListenConfig,
    pub remote: RemoteConfig,
    pub identity: IdentityConfig,
    pub peer: PeerConfig,
    #[serde(default)]
    pub outer_tls: OuterTlsConfig,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteConfig {
    pub address: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdentityConfig {
    pub private_key_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    pub server_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct OuterTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub server_name: Option<String>,
    /// An extra PEM trust anchor for the TLS-MITM acceptance harness. Production
    /// deployments should rely on the platform trust store instead.
    pub additional_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Timeouts {
    #[serde(default = "default_connect_seconds")]
    pub connect_seconds: u64,
    #[serde(default = "default_handshake_seconds")]
    pub handshake_seconds: u64,
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect_seconds: default_connect_seconds(),
            handshake_seconds: default_handshake_seconds(),
            idle_seconds: default_idle_seconds(),
        }
    }
}

const fn default_connect_seconds() -> u64 {
    10
}
const fn default_handshake_seconds() -> u64 {
    10
}
const fn default_idle_seconds() -> u64 {
    600
}

#[derive(Clone, Debug, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
        }
    }
}

const fn default_max_connections() -> usize {
    32
}

impl ClientConfig {
    pub fn from_toml(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("invalid client TOML")?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read client configuration {}", path.display()))?;
        Self::from_toml(&text)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.listen.address.ip().is_loopback() {
            bail!(
                "client listener must bind a loopback address, not {}",
                self.listen.address
            );
        }
        if self.remote.address.trim().is_empty() {
            bail!("remote address must not be empty");
        }
        if self.peer.server_public_key.trim().is_empty() {
            bail!("a pinned server public key is required");
        }
        if self.outer_tls.enabled
            && self
                .outer_tls
                .server_name
                .as_deref()
                .is_none_or(|server_name| server_name.trim().is_empty())
        {
            bail!("outer_tls.server_name is required when outer TLS is enabled");
        }
        if self.timeouts.connect_seconds == 0
            || self.timeouts.handshake_seconds == 0
            || self.timeouts.idle_seconds == 0
        {
            bail!("all timeouts must be positive");
        }
        if self.limits.max_connections == 0
            || self.limits.max_connections > MAX_CONCURRENT_CONNECTIONS
        {
            bail!("client connection limit must be between 1 and {MAX_CONCURRENT_CONNECTIONS}");
        }
        Ok(())
    }
}
