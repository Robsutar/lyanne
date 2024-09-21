use lyanne::packets::{Packet, PacketRegistry};
use serde::{Deserialize, Serialize};

pub fn new_packet_registry() -> PacketRegistry {
    let mut exit = PacketRegistry::with_essential();

    exit.add::<HelloPacket>();
    exit.add::<MessagePacket>();
    exit.add::<GoodbyePacket>();

    exit
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct HelloPacket {
    pub name: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct MessagePacket {
    pub message: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct GoodbyePacket {
    pub info: String,
}
