use std::net::SocketAddr;

/// Properties to bind a server with Tcp authenticator.
#[cfg(feature = "server")]
pub struct AuthTcpServerProperties {
    /// Addr to bind the Tcp socket.
    pub server_addr: SocketAddr,
}

/// Properties to connect a client with Tcp authenticator.
#[cfg(feature = "client")]
pub struct AuthTcpClientProperties {
    /// Addr to the server Tcp socket.
    pub server_addr: SocketAddr,
}
