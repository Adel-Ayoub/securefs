use std::net::SocketAddr;

// Network configuration parsed and validated from the environment. Malformed
// values fail loudly at startup with a clear message instead of silently
// falling back (a non-numeric DB_PORT previously fell through to the default).
pub struct NetConfig {
    pub server_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub db_port: u16,
}

impl NetConfig {
    pub fn from_env() -> Result<Self, String> {
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
pub fn parse_socket_addr(name: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{} must be an ip:port address, got '{}'", name, value))
}

pub fn parse_port(name: &str, value: &str) -> Result<u16, String> {
    value
        .parse()
        .map_err(|_| format!("{} must be a port number 0-65535, got '{}'", name, value))
}
