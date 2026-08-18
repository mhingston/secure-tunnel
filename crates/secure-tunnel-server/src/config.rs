use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use secure_tunnel::{MAX_CONCURRENT_CONNECTIONS, MAX_SERVER_STATIC_IDENTITIES};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: ListenConfig,
    pub destination: DestinationConfig,
    pub identity: IdentityConfig,
    pub authorized_clients: Vec<AuthorisedClient>,
    #[serde(default)]
    pub outer_tls: OuterTlsConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub timeouts: Timeouts,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DestinationConfig {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdentityConfig {
    pub private_key_file: PathBuf,
    /// Additional server private identities used only during a controlled
    /// key-rotation overlap. The primary identity remains first.
    #[serde(default)]
    pub additional_private_key_files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthorisedClient {
    pub name: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct OuterTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_record_bytes")]
    pub max_plaintext_record_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_plaintext_record_bytes: default_record_bytes(),
        }
    }
}
const fn default_max_connections() -> usize {
    32
}
const fn default_record_bytes() -> usize {
    16_384
}

#[derive(Clone, Debug, Deserialize)]
pub struct Timeouts {
    #[serde(default = "default_connect_seconds")]
    pub destination_connect_seconds: u64,
    #[serde(default = "default_handshake_seconds")]
    pub handshake_seconds: u64,
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
}
impl Default for Timeouts {
    fn default() -> Self {
        Self {
            destination_connect_seconds: default_connect_seconds(),
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

impl ServerConfig {
    pub fn from_toml(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("invalid server TOML")?;
        config.validate()?;
        Ok(config)
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read server configuration {}", path.display()))?;
        Self::from_toml(&text)
    }
    pub fn validate(&self) -> Result<()> {
        if !self.destination.address.ip().is_loopback() {
            bail!(
                "destination must be a fixed loopback address, not {}",
                self.destination.address
            );
        }
        if self.authorized_clients.is_empty() {
            bail!("at least one authorised client is required");
        }
        if self
            .authorized_clients
            .iter()
            .any(|client| client.name.trim().is_empty() || client.public_key.trim().is_empty())
        {
            bail!("authorised clients require a non-empty name and public key");
        }
        if self.identity.private_key_file.as_os_str().is_empty()
            || self
                .identity
                .additional_private_key_files
                .iter()
                .any(|path| path.as_os_str().is_empty())
        {
            bail!("server private key file paths must not be empty");
        }
        let identity_count = 1 + self.identity.additional_private_key_files.len();
        if identity_count > MAX_SERVER_STATIC_IDENTITIES {
            bail!(
                "at most {MAX_SERVER_STATIC_IDENTITIES} server static identities may be configured"
            );
        }
        let mut identity_paths = HashSet::new();
        identity_paths.insert(&self.identity.private_key_file);
        if self
            .identity
            .additional_private_key_files
            .iter()
            .any(|path| !identity_paths.insert(path))
        {
            bail!("server private key files must be distinct");
        }
        if self.limits.max_connections == 0
            || self.limits.max_connections > MAX_CONCURRENT_CONNECTIONS
            || self.limits.max_plaintext_record_bytes != 16_384
        {
            bail!(
                "version 1 requires a connection limit from 1 through {MAX_CONCURRENT_CONNECTIONS} and a 16384-byte plaintext record limit"
            );
        }
        if self.outer_tls.enabled && self.outer_tls.certificate_file.is_none() {
            bail!("outer_tls.certificate_file is required when outer TLS is enabled");
        }
        if self.outer_tls.enabled && self.outer_tls.private_key_file.is_none() {
            bail!("outer_tls.private_key_file is required when outer TLS is enabled");
        }
        if self.timeouts.destination_connect_seconds == 0
            || self.timeouts.handshake_seconds == 0
            || self.timeouts.idle_seconds == 0
        {
            bail!("all timeouts must be positive");
        }
        Ok(())
    }
}
