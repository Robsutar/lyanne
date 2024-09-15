//! Packets are the sets of data that are transferred over the network, represented by structs.

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    io,
};

use crate::{self as lyanne};

#[cfg(feature = "sd_bincode")]
pub use bincode;

#[cfg(any(feature = "sd_bincode"))]
pub extern crate lyanne_derive;
#[cfg(any(feature = "sd_bincode"))]
pub use lyanne_derive::Packet;

pub type PacketId = u16;
pub type PacketToDowncast = dyn Any + Send + Sync;

#[macro_export]
macro_rules! add_essential_packets {
    ($exit:expr) => {
        $exit.add::<lyanne::packets::ClientTickEndPacket>();
        $exit.add::<lyanne::packets::ServerTickEndPacket>();
        $exit.add::<lyanne::packets::EmptyPacket>();
    };
}

pub trait Packet: Sized + Debug + 'static + Any + Send + Sync {
    fn serialize_packet(&self) -> io::Result<Vec<u8>>;
    fn deserialize_packet(bytes: &[u8]) -> io::Result<Self>;

    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    type ClientSchedule: lyanne::bevy_ecs::schedule::ScheduleLabel;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    fn client_schedule() -> Self::ClientSchedule;

    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    type ServerSchedule: lyanne::bevy_ecs::schedule::ScheduleLabel;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    fn server_schedule() -> Self::ServerSchedule;
}

#[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
#[derive(lyanne::bevy_ecs::system::Resource)]
pub struct ClientPacketResource<P: Packet> {
    pub packet: Option<P>,
}

#[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
#[derive(lyanne::bevy_ecs::system::Resource)]
pub struct ServerPacketResource<P: Packet> {
    pub packet: Option<P>,
}

pub struct PacketRegistry {
    packet_type_ids: HashMap<TypeId, PacketId>,
    serde_map: HashMap<
        PacketId,
        (
            // Serialize, uses a `Packet`, and serialize it into a SerializedPacket
            Box<dyn Fn(&PacketToDowncast) -> io::Result<SerializedPacket> + Send + Sync>,
            // Deserialize, uses a `Vec<u8>`, and deserialize it into a Packet
            Box<dyn Fn(&[u8]) -> io::Result<Box<PacketToDowncast>> + Send + Sync>,
        ),
    >,
    last_id: PacketId,
}

impl PacketRegistry {
    pub fn empty() -> Self {
        Self {
            packet_type_ids: HashMap::new(),
            serde_map: HashMap::new(),
            last_id: 0,
        }
    }

    pub fn with_essential() -> Self {
        let mut exit = Self {
            packet_type_ids: HashMap::new(),
            serde_map: HashMap::new(),
            last_id: 0,
        };
        add_essential_packets!(exit);
        exit
    }

    pub fn add<P: Packet>(&mut self) -> PacketId {
        self.last_id += 1;
        let packet_id = self.last_id;
        let type_id = TypeId::of::<P>();

        let packet_id_copy = packet_id;
        let packet_id_bytes = packet_id_copy.to_le_bytes();
        let serialize = move |packet: &PacketToDowncast| -> io::Result<SerializedPacket> {
            let packet = packet.downcast_ref::<P>().ok_or_else(|| {
                return io::Error::new(io::ErrorKind::InvalidData, "Type mismatch");
            })?;

            let mut bytes = P::serialize_packet(packet)?;

            let packet_length = bytes.len() as PacketId;
            let packet_length_bytes = packet_length.to_le_bytes();

            let mut full_bytes: Vec<u8> = Vec::with_capacity(bytes.len() + 4);
            full_bytes.extend_from_slice(&packet_id_bytes);
            full_bytes.extend(packet_length_bytes);
            full_bytes.append(&mut bytes);

            Ok(SerializedPacket {
                packet_id: packet_id_copy,
                bytes: full_bytes,
            })
        };

        let deserialize = |bytes: &[u8]| -> io::Result<Box<PacketToDowncast>> {
            let packet = P::deserialize_packet(&bytes)?;
            Ok(Box::new(packet))
        };

        self.packet_type_ids.insert(type_id, packet_id);
        self.serde_map
            .insert(packet_id, (Box::new(serialize), Box::new(deserialize)));

        packet_id
    }

    pub fn check_essential(&self) -> bool {
        self.try_get_packet_id::<ClientTickEndPacket>().is_some()
            && self.try_get_packet_id::<ServerTickEndPacket>().is_some()
            && self.try_get_packet_id::<EmptyPacket>().is_some()
    }

    /// Get the if of the packet.
    ///
    /// # Returns
    /// - Some(&PacketId) if the packet is not registered.
    /// - None if the packet is not registered.
    pub fn try_get_packet_id<P: Packet>(&self) -> Option<&PacketId> {
        self.packet_type_ids.get(&TypeId::of::<P>())
    }

    /// Panic version of [`PacketRegistry::try_get_packet_id`].
    ///
    /// Get the if of the packet.
    ///
    /// # Panics
    /// If the packet is not registered.
    #[cfg(not(feature = "no_panics"))]
    pub fn get_packet_id<P: Packet>(&self) -> &PacketId {
        self.try_get_packet_id::<P>()
            .expect("Packet is not registered.")
    }

    /// Serializes a packet.
    ///
    /// # Errors
    /// If the packet is not in the registry, or the bytes serialization fails.
    pub fn try_serialize<P: Packet>(&self, packet: &P) -> io::Result<SerializedPacket> {
        let packet_id = self.try_get_packet_id::<P>();
        if let Some(packet_id) = packet_id {
            let (serialize, _) = self.serde_map.get(packet_id).unwrap();
            let serialized = serialize(packet)?;

            Ok(serialized)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packet id not found".to_owned(),
            ));
        }
    }

    /// Panic version of [`PacketRegistry::try_serialize`].
    ///
    /// Serializes a packet.
    ///
    /// # Panics
    /// If the packet is not in the registry, or the bytes serialization fails.
    #[cfg(not(feature = "no_panics"))]
    pub fn serialize<P: Packet>(&self, packet: &P) -> SerializedPacket {
        self.try_serialize(packet)
            .expect("Failed to serialize packet.")
    }

    /// Deserializes a packet.
    ///
    /// # Errors
    /// If the packet is not in the registry, or the bytes deserialization fails.
    pub fn try_deserialize(
        &self,
        serialized_packet: &SerializedPacket,
    ) -> io::Result<Box<PacketToDowncast>> {
        if let Some((_, deserialize)) = self.serde_map.get(&serialized_packet.packet_id) {
            let deserialized = deserialize(&serialized_packet.bytes[4..])?;
            Ok(deserialized)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packet id not found",
            ));
        }
    }

    /// Panic version of [`PacketRegistry::try_deserialize`].
    ///
    /// Deserializes a packet.
    ///
    /// # Panics
    /// If the packet is not in the registry, or the bytes deserialization fails.
    #[cfg(not(feature = "no_panics"))]
    pub fn deserialize(&self, serialized_packet: &SerializedPacket) -> Box<PacketToDowncast> {
        self.try_deserialize(serialized_packet)
            .expect("Failed to deserialize packet.")
    }

    pub fn empty_serialized_list(&self) -> SerializedPacketList {
        SerializedPacketList::single(
            self.try_serialize(&EmptyPacket)
                .expect("EmptyPacket was not registered."),
        )
    }
}

pub struct SerializedPacket {
    pub(crate) packet_id: PacketId,
    pub(crate) bytes: Vec<u8>,
}

impl SerializedPacket {
    pub fn clone(&self) -> Self {
        Self {
            packet_id: self.packet_id,
            bytes: self.bytes.clone(),
        }
    }

    pub fn read_first(buf: &[u8], packet_buf_index: usize) -> io::Result<SerializedPacket> {
        if buf.len() - packet_buf_index < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buf size is not big sufficient to read packet id and packet length",
            ));
        }

        let packet_id = PacketId::from_le_bytes([buf[packet_buf_index], buf[packet_buf_index + 1]]);
        let packet_length: PacketId =
            PacketId::from_le_bytes([buf[packet_buf_index + 2], buf[packet_buf_index + 3]]);

        let packet_size: usize = packet_length.into();
        if buf.len() < 4 + packet_buf_index + packet_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Buf size ({:}) is not big sufficient, minimal is {:?}",
                    buf.len(),
                    4 + packet_buf_index + packet_size
                ),
            ));
        } else {
            return Ok(SerializedPacket {
                packet_id,
                bytes: buf[packet_buf_index..4 + packet_buf_index + packet_size].to_vec(),
            });
        }
    }
}

#[derive(Debug)]
pub struct DeserializedMessageMap {
    inner: HashMap<PacketId, Vec<DeserializedPacket>>,
}

impl DeserializedMessageMap {
    /// The list (if there is some) of the packet type (`P`).
    ///
    /// That list will never be empty.
    /// # Errors
    /// - If the packet type (`P`) was not registered in `packet_registry`.
    /// - If the packet_map is invalid, and has packets that can not be converted to `P` in the list.
    pub fn try_collect_list<P: Packet>(
        &mut self,
        packet_registry: &PacketRegistry,
    ) -> io::Result<Option<Vec<P>>> {
        if let Some(packet_id) = packet_registry.try_get_packet_id::<P>() {
            if let Some(list) = self.inner.remove(&packet_id) {
                let mut exit = Vec::<P>::new();
                for packet in list {
                    if let Ok(downcast) = packet.packet.downcast::<P>() {
                        exit.push(*downcast);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Packet could not be converted into P.",
                        ));
                    }
                }
                Ok(Some(exit))
            } else {
                Ok(None)
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Packet is not registered.",
            ))
        }
    }

    /// Panic version of [`DeserializedMessageMap::try_collect_list`].
    ///
    /// The list (if there is some) of the packet type (`P`).
    ///
    /// That list will never be empty.
    /// # Panics
    /// - If the packet type (`P`) was not registered in `packet_registry`.
    /// - If the packet_map is invalid, and has packets that can not be converted to `P` in the list.
    #[cfg(not(feature = "no_panics"))]
    pub fn collect_list<P: Packet>(&mut self, packet_registry: &PacketRegistry) -> Option<Vec<P>> {
        self.try_collect_list(packet_registry)
            .expect("Failed to collect packets into list from map.")
    }
}

#[derive(Debug)]
pub struct DeserializedPacket {
    pub packet_id: PacketId,
    pub packet: Box<PacketToDowncast>,
}

impl DeserializedPacket {
    pub fn deserialize_list(
        buf: &[u8],
        packet_registry: &PacketRegistry,
    ) -> io::Result<Vec<DeserializedPacket>> {
        let mut packet_buf_index = 0;
        let mut received_packets: Vec<DeserializedPacket> = Vec::new();
        loop {
            if buf.len() == packet_buf_index {
                break;
            }

            match SerializedPacket::read_first(buf, packet_buf_index) {
                Ok(serialized_packet) => {
                    packet_buf_index += serialized_packet.bytes.len();
                    if let Some((_, deserialize)) =
                        packet_registry.serde_map.get(&serialized_packet.packet_id)
                    {
                        match deserialize(&serialized_packet.bytes[4..]) {
                            Ok(deserialized) => {
                                received_packets.push(DeserializedPacket {
                                    packet_id: serialized_packet.packet_id,
                                    packet: deserialized,
                                });
                            }
                            Err(e) => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                            }
                        }
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("packet id not registered: {}", serialized_packet.packet_id),
                        ));
                    }
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
        if received_packets.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The list has no packets.",
            ))
        } else {
            Ok(received_packets)
        }
    }

    pub fn deserialize_list_as_map(
        buf: &[u8],
        packet_registry: &PacketRegistry,
    ) -> io::Result<DeserializedMessageMap> {
        let mut packet_buf_index = 0;
        let mut received_packets: HashMap<PacketId, Vec<DeserializedPacket>> = HashMap::new();
        loop {
            if buf.len() == packet_buf_index {
                break;
            }

            match SerializedPacket::read_first(buf, packet_buf_index) {
                Ok(serialized_packet) => {
                    packet_buf_index += serialized_packet.bytes.len();
                    if let Some((_, deserialize)) =
                        packet_registry.serde_map.get(&serialized_packet.packet_id)
                    {
                        match deserialize(&serialized_packet.bytes[4..]) {
                            Ok(deserialized) => {
                                received_packets
                                    .entry(serialized_packet.packet_id)
                                    .or_insert_with(|| Vec::new())
                                    .push(DeserializedPacket {
                                        packet_id: serialized_packet.packet_id,
                                        packet: deserialized,
                                    });
                            }
                            Err(e) => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                            }
                        }
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("packet id not registered: {}", serialized_packet.packet_id),
                        ));
                    }
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
        if received_packets.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The list has no packets.",
            ))
        } else {
            Ok(DeserializedMessageMap {
                inner: received_packets,
            })
        }
    }
}

pub struct SerializedPacketList {
    pub(crate) bytes: Vec<u8>,
}

impl SerializedPacketList {
    /// Creates a SerializedPacketList from `stored`.
    ///
    /// # Errors
    /// If `stored` is empty.
    pub fn try_non_empty(stored: Vec<SerializedPacket>) -> Option<SerializedPacketList> {
        if stored.is_empty() {
            return None;
        }

        let total_size = stored
            .iter()
            .map(|packet| packet.bytes.len())
            .sum::<usize>();
        let mut bytes = Vec::with_capacity(total_size);

        for mut packet in stored {
            bytes.append(&mut packet.bytes);
        }

        Some(SerializedPacketList { bytes })
    }

    /// Panic version of [`SerializedPacketList::try_non_empty`].
    ///
    /// Creates a SerializedPacketList from `stored`.
    ///
    /// # Panics
    /// If `stored` is empty.
    #[cfg(not(feature = "no_panics"))]
    pub fn non_empty(stored: Vec<SerializedPacket>) -> SerializedPacketList {
        SerializedPacketList::try_non_empty(stored).expect("SerializedPacketList can not be empty")
    }

    /// Creates a SerializedPacketList with a single packet.
    pub fn single(stored: SerializedPacket) -> SerializedPacketList {
        SerializedPacketList::try_non_empty(vec![stored]).unwrap()
    }
}

#[derive(Debug)]
pub struct ClientTickEndPacket;
impl Packet for ClientTickEndPacket {
    fn serialize_packet(&self) -> std::io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn deserialize_packet(_bytes: &[u8]) -> std::io::Result<Self> {
        Ok(Self)
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    type ClientSchedule = ClientTickEndPacketClientSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    fn client_schedule() -> Self::ClientSchedule {
        ClientTickEndPacketClientSchedule
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    type ServerSchedule = ClientTickEndPacketServerSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    fn server_schedule() -> Self::ServerSchedule {
        ClientTickEndPacketServerSchedule
    }
}
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientTickEndPacketClientSchedule;
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientTickEndPacketServerSchedule;

#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "client")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientTickEndPacketClientSchedule;
#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "server")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientTickEndPacketServerSchedule;

#[derive(Debug)]
pub struct ServerTickEndPacket;
impl Packet for ServerTickEndPacket {
    fn serialize_packet(&self) -> std::io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn deserialize_packet(_bytes: &[u8]) -> std::io::Result<Self> {
        Ok(Self)
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    type ClientSchedule = ServerTickEndPacketClientSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    fn client_schedule() -> Self::ClientSchedule {
        ServerTickEndPacketClientSchedule
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    type ServerSchedule = ServerTickEndPacketServerSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    fn server_schedule() -> Self::ServerSchedule {
        ServerTickEndPacketServerSchedule
    }
}
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTickEndPacketClientSchedule;
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTickEndPacketServerSchedule;

#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "client")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTickEndPacketClientSchedule;
#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "server")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTickEndPacketServerSchedule;

#[derive(Debug)]
pub struct EmptyPacket;
impl Packet for EmptyPacket {
    fn serialize_packet(&self) -> std::io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn deserialize_packet(_bytes: &[u8]) -> std::io::Result<Self> {
        Ok(Self)
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    type ClientSchedule = EmptyPacketClientSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
    fn client_schedule() -> Self::ClientSchedule {
        EmptyPacketClientSchedule
    }

    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    type ServerSchedule = EmptyPacketServerSchedule;
    #[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
    fn server_schedule() -> Self::ServerSchedule {
        EmptyPacketServerSchedule
    }
}
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "client"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmptyPacketClientSchedule;
#[allow(dead_code)]
#[cfg(all(feature = "bevy_packet_schedules", feature = "server"))]
#[derive(lyanne::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmptyPacketServerSchedule;

#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "client")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmptyPacketClientSchedule;
#[allow(dead_code)]
#[cfg(not(all(feature = "bevy_packet_schedules", feature = "server")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmptyPacketServerSchedule;
