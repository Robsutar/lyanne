use std::any::Any;

use tokio::net::UdpSocket;

use crate::packets::Packet;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub type Socket = UdpSocket;
