use tokio::net::UdpSocket;
use uuid::Uuid;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub type Socket = UdpSocket;
pub type ClientIdentifier = Uuid;
