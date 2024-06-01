use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    io,
    marker::PhantomData,
    net::SocketAddr,
};

#[cfg(feature = "use_bevy")]
use bevy::ecs::system::Commands;
#[cfg(feature = "use_bevy")]
use bevy::ecs::system::Resource;
#[cfg(feature = "use_bevy")]
use bevy::ecs::world::World;
use bevy::log::tracing_subscriber::reload::Error;
use serde::{Deserialize, Serialize};

pub use lyanne_derive::Packet;
pub trait Packet:
    Serialize + for<'de> Deserialize<'de> + Debug + 'static + Any + Send + Sync
{
    #[cfg(all(feature = "use_bevy", feature = "client"))]
    fn run_client_schedule(
        world: &mut World,
    ) -> Result<(), bevy::ecs::world::error::TryRunScheduleError>;

    #[cfg(all(feature = "use_bevy", feature = "server"))]
    fn run_server_schedule(
        world: &mut World,
    ) -> Result<(), bevy::ecs::world::error::TryRunScheduleError>;
}

pub type PacketToDowncast = dyn Any + Send;

#[cfg(all(feature = "use_bevy", feature = "client"))]
#[derive(Resource)]
pub struct ClientPacketResource<P: Packet> {
    pub packet: Option<P>,
}

#[cfg(all(feature = "use_bevy", feature = "server"))]
#[derive(Resource)]
pub struct ServerPacketResource<P: Packet> {
    pub packet: Option<P>,
}

pub struct PacketRegistry {
    pub(crate) packet_type_ids: HashMap<TypeId, u16>,
    pub(crate) serde_map: HashMap<
        u16,
        (
            // Serialize, uses a `Packet`, and serialize it into a SerializedPacket
            Box<dyn Fn(&PacketToDowncast) -> io::Result<SerializedPacket> + Send + Sync>,
            // Deserialize, uses a `Vec<u8>`, and deserialize it into a Packet
            Box<dyn Fn(&[u8]) -> io::Result<Box<PacketToDowncast>> + Send + Sync>,
        ),
    >,
    #[cfg(all(feature = "use_bevy", feature = "client"))]
    pub(crate) bevy_client_caller_map:
        HashMap<u16, Box<dyn Fn(&mut Commands, Box<PacketToDowncast>) -> () + Send + Sync>>,
    #[cfg(all(feature = "use_bevy", feature = "server"))]
    pub(crate) bevy_server_caller_map:
        HashMap<u16, Box<dyn Fn(&mut Commands, Box<PacketToDowncast>) -> () + Send + Sync>>,
    last_id: u16,
}

impl PacketRegistry {
    pub fn new() -> Self {
        let mut exit = Self {
            packet_type_ids: HashMap::new(),
            serde_map: HashMap::new(),
            last_id: 0,
            #[cfg(all(feature = "use_bevy", feature = "client"))]
            bevy_client_caller_map: HashMap::new(),
            #[cfg(all(feature = "use_bevy", feature = "server"))]
            bevy_server_caller_map: HashMap::new(),
        };
        exit.add::<FooPacket>();
        exit.add::<BarPacket>();
        exit
    }

    pub fn add<P: Packet>(&mut self) {
        self.last_id += 1;
        let packet_id = self.last_id;
        let type_id = TypeId::of::<P>();

        let packet_id_copy = packet_id;
        let packet_id_bytes = packet_id_copy.to_be_bytes();
        let serialize = move |packet: &PacketToDowncast| -> io::Result<SerializedPacket> {
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
                bytes: full_bytes,
            })
        };

        let deserialize = |bytes: &[u8]| -> io::Result<Box<PacketToDowncast>> {
            let packet: P = bincode::deserialize(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(Box::new(packet))
        };

        self.packet_type_ids.insert(type_id, packet_id);
        self.serde_map
            .insert(packet_id, (Box::new(serialize), Box::new(deserialize)));

        #[cfg(all(feature = "use_bevy", feature = "client"))]
        self.bevy_client_caller_map.insert(
            packet_id,
            Box::new(
                |commands: &mut Commands, as_any: Box<PacketToDowncast>| -> () {
                    let packet = *as_any.downcast::<P>().unwrap();
                    commands.add(move |world: &mut World| {
                        world.insert_resource(ClientPacketResource::<P> {
                            packet: Some(packet),
                        });
                        if let Err(e) = P::run_client_schedule(world) {
                            println!("failed to run client schedule, but that should be ok {}", e);
                        }
                        world.remove_resource::<ClientPacketResource<P>>().unwrap();
                    });
                },
            ),
        );

        #[cfg(all(feature = "use_bevy", feature = "server"))]
        self.bevy_server_caller_map.insert(
            packet_id,
            Box::new(
                |commands: &mut Commands, as_any: Box<PacketToDowncast>| -> () {
                    let packet = *as_any.downcast::<P>().unwrap();
                    commands.add(move |world: &mut World| {
                        world.insert_resource(ServerPacketResource::<P> {
                            packet: Some(packet),
                        });
                        if let Err(e) = P::run_server_schedule(world) {
                            println!("failed to run server schedule, but that should be ok {}", e);
                        }
                        world.remove_resource::<ServerPacketResource<P>>().unwrap();
                    });
                },
            ),
        );
    }

    pub fn serialize<P: Packet>(&self, packet: &P) -> io::Result<SerializedPacket> {
        let packet_id = self.packet_type_ids.get(&TypeId::of::<P>());
        if let Some(packet_id) = packet_id {
            let (serialize, _) = self.serde_map.get(packet_id).unwrap();
            let serialized = serialize(packet)?;

            Ok(serialized)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet id not found",
            ))
        }
    }

    pub fn deserialize(
        &self,
        serialized_packet: &SerializedPacket,
    ) -> io::Result<Box<PacketToDowncast>> {
        if let Some((_, deserialize)) = self.serde_map.get(&serialized_packet.packet_id) {
            let deserialized = deserialize(&serialized_packet.bytes[4..])?;
            Ok(deserialized)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet_id not found",
            ))
        }
    }

    #[cfg(all(feature = "use_bevy", feature = "server"))]
    pub fn bevy_server_call(
        &self,
        commands: &mut Commands,
        deserialized_packet: DeserializedPacket,
    ) {
        let call = self
            .bevy_server_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(commands, deserialized_packet.packet);
    }

    #[cfg(all(feature = "use_bevy", feature = "client"))]
    pub fn bevy_client_call(
        &self,
        commands: &mut Commands,
        deserialized_packet: DeserializedPacket,
    ) {
        let call = self
            .bevy_client_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(commands, deserialized_packet.packet);
    }
}

pub struct SerializedPacket {
    pub(crate) packet_id: u16,
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
                bytes: buf[packet_buf_index..4 + packet_buf_index + packet_size].to_vec(),
            })
        }
    }
}

#[derive(Clone)]
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

pub struct DeserializedPacket {
    pub(crate) packet_id: u16,
    pub(crate) packet: Box<PacketToDowncast>,
}

impl DeserializedPacket {
    pub fn deserialize(
        buf: &[u8],
        packet_registry: &PacketRegistry,
    ) -> io::Result<Vec<DeserializedPacket>> {
        let mut packet_buf_index = 0;
        let mut received_packets = Vec::<DeserializedPacket>::new();
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
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("packet id not registered: {}", serialized_packet.packet_id),
                        ));
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(received_packets)
    }
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct AuthPacket {
    pub registry_length: u16,
    pub additional_bytes: Vec<u8>,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct FooPacket {
    pub message: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct BarPacket {
    pub message: String,
}
