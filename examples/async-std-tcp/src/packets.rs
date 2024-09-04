use lyanne::packets::{Packet, PacketRegistry};
use serde::{Deserialize, Serialize};

pub fn new_packet_registry() -> PacketRegistry {
    let mut exit = PacketRegistry::with_essential();

    exit.add::<HelloPacket>();
    exit.add::<MessagePacket>();

    exit
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct HelloPacket {
    pub player_name: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct MessagePacket {
    pub message: String,
}
