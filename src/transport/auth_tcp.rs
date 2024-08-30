use std::net::SocketAddr;

#[cfg(feature = "server")]
pub struct AuthTcpServerProperties {
    pub server_name: &'static str,
    pub server_addr: SocketAddr,
}

#[cfg(feature = "client")]
pub struct AuthTcpClientProperties {
    pub server_name: &'static str,
    pub server_addr: SocketAddr,
}
