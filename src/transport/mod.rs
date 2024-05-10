use tokio::net::UdpSocket;

use crate::packets::Packet;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub type Socket = UdpSocket;

pub struct EventReceiver {}
impl EventReceiver {
    pub fn call_event<P: Packet>(&mut self, packet: &mut P) {
        println!("packet event called: {:?}", packet);
    }
}
