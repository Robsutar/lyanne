use lyanne::packets::{Packet, PacketRegistry};
use serde::{Deserialize, Serialize};

pub fn new_packet_registry() -> PacketRegistry {
    let mut exit = PacketRegistry::with_essential();

    exit.add::<HelloPacket>();
    exit.add::<ChatContextPacket>();
    exit.add::<MessagePacket>();
    exit.add::<ChatLinePacket>();
    exit.add::<LeavePacket>();
    exit.add::<AuthenticationFailedPacket>();

    exit
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct HelloPacket {
    pub player_name: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct ChatContextPacket {
    pub connected_players: Vec<String>,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct MessagePacket {
    pub message: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct ChatLinePacket {
    pub line: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct LeavePacket {
    pub message: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct AuthenticationFailedPacket {
    pub justification: String,
}
