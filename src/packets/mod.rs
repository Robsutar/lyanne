use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    io,
};

use serde::{Deserialize, Serialize};

use crate::transport::EventReceiver;

pub trait Packet: Serialize + for<'de> Deserialize<'de> + Debug + 'static + Any {}

pub struct PacketRegistry {
    pub(crate) packet_type_ids: HashMap<TypeId, u16>,
    pub(crate) packet_map: HashMap<
        u16,
        (
            // Serialize, uses a `Packet`, and serialize it into a SerializedPacket
            Box<dyn Fn(&dyn Any) -> io::Result<SerializedPacket>>,
            // Deserialize, uses a `Vec<u8>`, and deserialize it into a Packet
            Box<dyn Fn(&[u8]) -> io::Result<Box<dyn Any>>>,
            Box<dyn Fn(&mut EventReceiver, Box<dyn Any>) -> ()>,
        ),
    >,
    last_id: u16,
}

impl PacketRegistry {
    pub fn new() -> Self {
        Self {
            packet_type_ids: HashMap::new(),
            packet_map: HashMap::new(),
            last_id: 0,
        }
        .add::<FooPacket>()
        .add::<BarPacket>()
    }

    pub fn add<P: Packet>(mut self) -> Self {
        self.last_id += 1;
        let packet_id = self.last_id;
        let type_id = TypeId::of::<P>();

        let packet_id_copy = packet_id;
        let packet_id_bytes = packet_id_copy.to_be_bytes();
        let serialize = move |packet: &dyn Any| -> io::Result<SerializedPacket> {
            let packet = packet
                .downcast_ref::<P>()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "type mismatch"))?;

            let bytes =
                bincode::serialize(packet).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let packet_length = bytes.len() as u16;
            let packet_length_bytes = packet_length.to_be_bytes();

            let mut full_bytes: Vec<u8> = Vec::with_capacity(bytes.len() + 4);
            full_bytes.extend_from_slice(&packet_id_bytes);
            full_bytes.extend_from_slice(&packet_length_bytes);
            full_bytes.extend_from_slice(&bytes);

            Ok(SerializedPacket {
                packet_id: packet_id_copy,
                packet_length,
                bytes: full_bytes,
            })
        };

        let deserialize = |bytes: &[u8]| -> io::Result<Box<dyn Any>> {
            let packet: P = bincode::deserialize(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(Box::new(packet))
        };

        let call = |event_receiver: &mut EventReceiver, mut as_any: Box<dyn Any>| -> () {
            let packet = as_any.downcast_mut::<P>().unwrap();
            event_receiver.call_event::<P>(packet);
        };
        //TODO: println!("packet registered: {:?}, {:?}", type_id, packet_id);

        self.packet_type_ids.insert(type_id, packet_id);
        self.packet_map.insert(
            packet_id,
            (Box::new(serialize), Box::new(deserialize), Box::new(call)),
        );
        self
    }

    pub fn serialize<P: Packet>(&self, packet: &P) -> io::Result<SerializedPacket> {
        let packet_id = self.packet_type_ids.get(&TypeId::of::<P>());
        if let Some(packet_id) = packet_id {
            let (serialize, _, _) = self.packet_map.get(packet_id).unwrap();
            let serialized = serialize(packet)?;

            Ok(serialized)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet id not found",
            ))
        }
    }

    pub fn deserialize(&self, serialized_packet: &SerializedPacket) -> io::Result<Box<dyn Any>> {
        if let Some((_, deserialize, _)) = self.packet_map.get(&serialized_packet.packet_id) {
            let deserialized = deserialize(&serialized_packet.bytes[4..])?;
            Ok(deserialized)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet_id not found",
            ))
        }
    }
}

pub struct SerializedPacket {
    pub(crate) packet_id: u16,
    /// OBS: that length is NOT equals than `bytes`, is equals to
    /// ( `bytes.len()` - byte len of `packet_id` (2) - byte len of `packet_length` (2) )
    pub(crate) packet_length: u16,
    pub(crate) bytes: Vec<u8>,
}

impl SerializedPacket {
    pub fn read_first(buf: &[u8], packet_buf_index: usize) -> io::Result<SerializedPacket> {
        let packet_id = u16::from_be_bytes([buf[packet_buf_index], buf[packet_buf_index + 1]]);
        let packet_length: u16 =
            u16::from_be_bytes([buf[packet_buf_index + 2], buf[packet_buf_index + 3]]);

        let packet_size: usize = packet_length.into();
        if buf.len() < 4 + packet_buf_index + packet_size {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "buf len ({:}) is not big sufficient, minimal is {:?}",
                    buf.len(),
                    4 + packet_buf_index + packet_size
                ),
            ))
        } else {
            Ok(SerializedPacket {
                packet_id,
                packet_length,
                bytes: buf[packet_buf_index..4 + packet_buf_index + packet_size].to_vec(),
            })
        }
    }
}

pub struct SerializedPacketList {
    pub(crate) bytes: Vec<u8>,
}

impl SerializedPacketList {
    pub fn create(stored: Vec<SerializedPacket>) -> SerializedPacketList {
        let total_size = stored
            .iter()
            .map(|packet| packet.bytes.len())
            .sum::<usize>();
        let mut bytes = Vec::with_capacity(total_size);

        for packet in stored {
            bytes.extend(packet.bytes);
        }

        SerializedPacketList { bytes }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthPacket {
    pub registry_length: u16,
    pub additional_bytes: Vec<u8>,
}

impl Packet for AuthPacket {}

#[derive(Deserialize, Serialize, Debug)]
pub struct FooPacket {
    pub message: String,
}

impl Packet for FooPacket {}

#[derive(Deserialize, Serialize, Debug)]
pub struct BarPacket {
    pub message: String,
}

impl Packet for BarPacket {}
