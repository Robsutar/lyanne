use std::{collections::HashMap, time::Duration};

use bevy::{
    math::{Rect, Vec2},
    prelude::World,
};
#[cfg(feature = "client")]
use lyanne::packets::ClientPacketResource;
#[cfg(feature = "server")]
use lyanne::packets::ServerPacketResource;
use lyanne::{
    add_essential_packets,
    packets::{DeserializedPacket, Packet, PacketId, PacketRegistry, PacketToDowncast},
};

use serde::{Deserialize, Serialize};
pub struct BevyPacketCaller {
    #[cfg(feature = "client")]
    client_caller_map:
        HashMap<PacketId, Box<dyn Fn(&mut World, Box<PacketToDowncast>) -> () + Send + Sync>>,
    #[cfg(feature = "server")]
    server_caller_map:
        HashMap<PacketId, Box<dyn Fn(&mut World, Box<PacketToDowncast>) -> () + Send + Sync>>,
}

impl BevyPacketCaller {
    fn new() -> Self {
        Self {
            #[cfg(feature = "client")]
            client_caller_map: HashMap::new(),
            #[cfg(feature = "server")]
            server_caller_map: HashMap::new(),
        }
    }

    fn add<P: Packet>(&mut self, packet_id: PacketId) {
        #[cfg(feature = "client")]
        self.client_caller_map.insert(
            packet_id,
            Box::new(|world: &mut World, as_any: Box<PacketToDowncast>| -> () {
                let packet = *as_any.downcast::<P>().unwrap();
                world.insert_resource(ClientPacketResource::<P> {
                    packet: Some(packet),
                });
                let _ = world.try_run_schedule(P::client_schedule());
                world.remove_resource::<ClientPacketResource<P>>().unwrap();
            }),
        );

        #[cfg(feature = "server")]
        self.server_caller_map.insert(
            packet_id,
            Box::new(|world: &mut World, as_any: Box<PacketToDowncast>| -> () {
                let packet = *as_any.downcast::<P>().unwrap();
                world.insert_resource(ServerPacketResource::<P> {
                    packet: Some(packet),
                });
                let _ = world.try_run_schedule(P::server_schedule());
                world.remove_resource::<ServerPacketResource<P>>().unwrap();
            }),
        );
    }

    #[cfg(feature = "server")]
    pub fn server_call(&self, world: &mut World, deserialized_packet: DeserializedPacket) {
        let call = self
            .server_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(world, deserialized_packet.packet);
    }

    #[cfg(feature = "client")]
    pub fn client_call(&self, world: &mut World, deserialized_packet: DeserializedPacket) {
        let call = self
            .client_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(world, deserialized_packet.packet);
    }
}

pub struct PacketManagers {
    pub packet_registry: PacketRegistry,
    pub bevy_caller: BevyPacketCaller,
}

impl PacketManagers {
    pub fn add<P: Packet>(&mut self) {
        let packet_id = self.packet_registry.add::<P>();
        self.bevy_caller.add::<P>(packet_id);
    }
}
impl Default for PacketManagers {
    fn default() -> Self {
        let mut exit = Self {
            packet_registry: PacketRegistry::empty(),
            bevy_caller: BevyPacketCaller::new(),
        };

        add_essential_packets!(exit);
        exit.add::<GameStartPacket>();
        exit.add::<PlayerPositionPacket>();
        exit.add::<SelfCommandUpdatePacket>();
        exit.add::<ClackPacket>();
        exit.add::<PointPacket>();
        exit.add::<MatchFinished>();
        exit.add::<ConnectionRefuseMessage>();

        exit
    }
}

pub const WINDOW_SIZE: Vec2 = Vec2::new(800.0, 600.0);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GameConfig {
    pub max_points: usize,
    pub max_time: Duration,
    pub arena: Rect,
    pub player_bar_size: Vec2,
    pub player_movement_speed: f32,
    pub goal_min_max_y: (f32, f32),
    pub ball_radius: f32,
    pub ball_speed_multiplier: f32,
}

impl Default for GameConfig {
    fn default() -> Self {
        let max_time = Duration::from_secs(180);
        Self {
            max_points: 3,
            max_time,
            arena: Rect::new(
                -WINDOW_SIZE.x / 2.0 + 10.0,
                -WINDOW_SIZE.y / 3.0,
                WINDOW_SIZE.x / 2.0 - 10.0,
                WINDOW_SIZE.y / 3.0,
            ),
            player_bar_size: Vec2::new(150.0, 150.0),
            player_movement_speed: 2.0,
            goal_min_max_y: (-10.0, 10.0),
            ball_radius: 5.0,
            ball_speed_multiplier: 1.1,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub enum PlayerSide {
    Left,
    Right,
}
impl PlayerSide {
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub enum FinishCause {
    TimeIsOver,
    MaxPoints,
    Forfeit,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct AuthenticationPacket {
    pub player_name: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct GameStartPacket {
    pub owned_type: PlayerSide,
    pub enemy_name: String,
    pub config: GameConfig,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct PlayerPositionPacket {
    pub player: PlayerSide,
    pub new_y: f32,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub enum SelfCommandUpdatePacket {
    None,
    Up,
    Down,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct ClackPacket;

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct PointPacket {
    pub side: PlayerSide,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct MatchFinished {
    pub winner: PlayerSide,
    pub cause: FinishCause,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct ConnectionRefuseMessage {
    pub message: String,
}
