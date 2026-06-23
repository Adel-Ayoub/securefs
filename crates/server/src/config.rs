use std::net::SocketAddr;

/// Error from parsing network configuration out of the environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{name} must be an ip:port address, got '{value}'")]
    BadSocketAddr { name: String, value: String },
    #[error("{name} must be a port number 0-65535, got '{value}'")]
    BadPort { name: String, value: String },
}

// Network configuration parsed and validated from the environment. Malformed
// values fail loudly at startup with a clear message instead of silently
// falling back (a non-numeric DB_PORT previously fell through to the default).
pub struct NetConfig {
    pub server_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub db_port: u16,
}

impl NetConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            server_addr: parse_socket_addr(
                "SERVER_ADDR",
                &env_or("SERVER_ADDR", "127.0.0.1:8080"),
            )?,
            health_addr: parse_socket_addr(
                "HEALTH_ADDR",
                &env_or("HEALTH_ADDR", "127.0.0.1:8081"),
            )?,
            db_port: parse_port("DB_PORT", &env_or("DB_PORT", "5431"))?,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// Bind addresses must be ip:port (e.g. 0.0.0.0:8080), not a hostname.
pub fn parse_socket_addr(name: &str, value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::BadSocketAddr {
        name: name.to_string(),
        value: value.to_string(),
    })
}

pub fn parse_port(name: &str, value: &str) -> Result<u16, ConfigError> {
    value.parse().map_err(|_| ConfigError::BadPort {
        name: name.to_string(),
        value: value.to_string(),
    })
}
