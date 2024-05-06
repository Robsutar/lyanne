pub struct Packet {}

impl Packet {
    pub fn serialize_list(list: &Vec<Packet>) -> SerializedPackets {
        //TODO:
        SerializedPackets { size: list.len() }
    }
}

pub struct SerializedPackets {
    pub size: usize,
}

impl SerializedPackets {
    pub(crate) fn as_buff(&self) -> Vec<u8> {
        //TODO:
        format!("Boomba! {:?}", self.size).into_bytes()
    }
}
