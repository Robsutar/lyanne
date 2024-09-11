use lyanne::packets::{Packet, PacketRegistry};

pub fn new_packet_registry() -> PacketRegistry {
    let mut exit = PacketRegistry::with_essential();

    exit.add::<HelloPacket>();
    exit.add::<MessagePacket>();

    exit
}

// Here the example differs from smol-simple, no derive from Packet.
#[derive(Debug)]
pub struct HelloPacket {
    pub player_name: String,
}

// Here the example differs from smol-simple, manual serialization/deserialization.
impl Packet for HelloPacket {
    fn serialize_packet(&self) -> std::io::Result<Vec<u8>> {
        Ok(self.player_name.clone().into_bytes())
    }

    fn deserialize_packet(bytes: &[u8]) -> std::io::Result<Self> {
        match String::from_utf8(bytes.to_vec()) {
            Ok(player_name) => Ok(Self { player_name }),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        }
    }
}

// Here the example differs from smol-simple, no derive from Packet.
#[derive(Debug)]
pub struct MessagePacket {
    pub message: String,
}

// Here the example differs from smol-simple, manual serialization/deserialization.
impl Packet for MessagePacket {
    fn serialize_packet(&self) -> std::io::Result<Vec<u8>> {
        Ok(self.message.clone().into_bytes())
    }

    fn deserialize_packet(bytes: &[u8]) -> std::io::Result<Self> {
        match String::from_utf8(bytes.to_vec()) {
            Ok(message) => Ok(Self { message }),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        }
    }
}
