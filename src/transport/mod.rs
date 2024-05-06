use tokio::net::UdpSocket;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub type Socket = UdpSocket;
