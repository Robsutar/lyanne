use std::collections::HashMap;

use bevy::prelude::{Commands, World};
#[cfg(feature = "client")]
use lyanne::packets::ClientPacketResource;
#[cfg(feature = "server")]
use lyanne::packets::ServerPacketResource;
use lyanne::{
    add_essential_packets,
    packets::{
        DeserializedPacket, Packet, PacketId, PacketRegistry, PacketToDowncast, ServerTickEndPacket,
    },
};

use serde::{Deserialize, Serialize};
pub struct BevyPacketCaller {
    #[cfg(feature = "client")]
    client_caller_map:
        HashMap<PacketId, Box<dyn Fn(&mut Commands, Box<PacketToDowncast>) -> () + Send + Sync>>,
    #[cfg(feature = "server")]
    server_caller_map:
        HashMap<PacketId, Box<dyn Fn(&mut Commands, Box<PacketToDowncast>) -> () + Send + Sync>>,
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
            Box::new(
                |commands: &mut Commands, as_any: Box<PacketToDowncast>| -> () {
                    let packet = *as_any.downcast::<P>().unwrap();
                    commands.add(move |world: &mut World| {
                        world.insert_resource(ClientPacketResource::<P> {
                            packet: Some(packet),
                        });
                        let _ = P::run_client_schedule(world);
                        world.remove_resource::<ClientPacketResource<P>>().unwrap();
                    });
                },
            ),
        );

        #[cfg(feature = "server")]
        self.server_caller_map.insert(
            packet_id,
            Box::new(
                |commands: &mut Commands, as_any: Box<PacketToDowncast>| -> () {
                    let packet = *as_any.downcast::<P>().unwrap();
                    commands.add(move |world: &mut World| {
                        world.insert_resource(ServerPacketResource::<P> {
                            packet: Some(packet),
                        });
                        let _ = P::run_server_schedule(world);
                        world.remove_resource::<ServerPacketResource<P>>().unwrap();
                    });
                },
            ),
        );
    }

    #[cfg(feature = "server")]
    pub fn server_call(&self, commands: &mut Commands, deserialized_packet: DeserializedPacket) {
        let call = self
            .server_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(commands, deserialized_packet.packet);
    }

    #[cfg(feature = "client")]
    pub fn client_call(&self, commands: &mut Commands, deserialized_packet: DeserializedPacket) {
        let call = self
            .client_caller_map
            .get(&deserialized_packet.packet_id)
            .unwrap();
        call(commands, deserialized_packet.packet);
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
            packet_registry: PacketRegistry::with_essential(),
            bevy_caller: BevyPacketCaller::new(),
        };

        add_essential_packets!(exit);
        exit.add::<FooPacket>();
        exit.add::<BarPacket>();

        exit
    }
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct FooPacket {
    pub message: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
pub struct BarPacket {
    pub message: String,
}
