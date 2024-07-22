pub mod game;

use std::{sync::Arc, time::Duration};

use bevy::{app::ScheduleRunnerPlugin, log::LogPlugin, prelude::*, tasks::futures_lite::future};
use bevy_ping_pong::{
    BarPacket, BarPacketClientSchedule, BevyPacketCaller, FooPacket, FooPacketClientSchedule,
    PacketManagers,
};
use lyanne::transport::client::{Client, ClientTickResult, ConnectError, ConnectResult};
use lyanne::transport::{MessagingProperties, ReadHandlerProperties};
use lyanne::{packets::ClientPacketResource, rt::TaskHandle};
use lyanne::{packets::SerializedPacketList, transport::client::ClientProperties};
use rand::{thread_rng, Rng};

#[derive(Component)]
struct ClientConnecting {
    bevy_caller: Option<BevyPacketCaller>,
    task: TaskHandle<Result<ConnectResult, ConnectError>>,
}

#[derive(Component)]
struct ClientConnected {
    client: Option<Client>,
    bevy_caller: BevyPacketCaller,
}

fn main() {
    App::default()
        // Plugins
        .add_plugins(TaskPoolPlugin::default())
        .add_plugins(TypeRegistrationPlugin::default())
        .add_plugins(FrameCountPlugin::default())
        .add_plugins(ScheduleRunnerPlugin::run_loop(Duration::from_millis(3)))
        .add_plugins(LogPlugin::default())
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, client_tick)
        .add_systems(FooPacketClientSchedule, foo_read)
        .add_systems(BarPacketClientSchedule, bar_read)
        .add_systems(BarPacketClientSchedule, bar_second_read)
        .run();
}

fn init(mut commands: Commands) {
    let remote_addr = "127.0.0.1:8822".parse().unwrap();
    let packet_managers = PacketManagers::default();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());

    let authentication_packets = vec![packet_managers.packet_registry.serialize(&FooPacket {
        message: "Auth me!!!".to_string(),
    })];

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_managers.packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        SerializedPacketList::create(authentication_packets),
    );

    commands.spawn(ClientConnecting {
        bevy_caller: Some(packet_managers.bevy_caller),
        task: connect_handle,
    });
}

fn foo_read(mut packet: ResMut<ClientPacketResource<FooPacket>>) {
    let packet = packet.packet.take();
    //println!("xaxa! {:?}", packet);
}

fn bar_read(mut packet: ResMut<ClientPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    //println!("pepe! {:?}", packet);
}

fn bar_second_read(mut packet: ResMut<ClientPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    //println!("pepe TWO! {:?}", packet);
}

fn read_bind_result(mut commands: Commands, mut query: Query<(Entity, &mut ClientConnecting)>) {
    for (entity, mut client_connecting) in query.iter_mut() {
        if let Some(connect) = future::block_on(future::poll_once(&mut client_connecting.task)) {
            commands.entity(entity).despawn();

            match connect {
                Ok(connect_result) => {
                    let client_connected = ClientConnected {
                        client: Some(connect_result.client),
                        bevy_caller: client_connecting.bevy_caller.take().unwrap(),
                    };
                    info!(
                        "Client connected, first message size: {:?}",
                        connect_result.message.packets.len()
                    );

                    commands.spawn(client_connected);
                }
                Err(err) => {
                    error!("Failed to bind client: {}", err);
                }
            }
        }
    }
}

fn client_tick(mut commands: Commands, mut query: Query<(Entity, &mut ClientConnected)>) {
    for (entity, mut client_connected) in query.iter_mut() {
        if false {
            let mut rng = thread_rng();
            if rng.gen_bool(0.01) {
                info!("Disconnecting from the server");

                let client = client_connected.client.take().unwrap();
                commands.entity(entity).despawn();

                let message = Some(SerializedPacketList::create(vec![client
                    .packet_registry()
                    .serialize(&BarPacket {
                        message: "We finished here...".to_owned(),
                    })]));
                let handle = client.disconnect(message);

                let result = future::block_on(handle);
                panic!("Client disconnected itself: {:?}", result.state);
            }
        } else {
            let client = client_connected.client.as_ref().unwrap();
            let tick = client.tick_start();
            match tick {
                ClientTickResult::ReceivedMessage(message) => {
                    if true {
                        let mut rng = thread_rng();
                        for _ in 0..(rng.gen_range(500..501) / 2) {
                            let message = format!("Random str: {:?}", rng.gen::<i32>());
                            if rng.gen_bool(0.5) {
                                let packet = FooPacket { message };
                                client.send_packet(&packet);
                            } else {
                                let packet = BarPacket { message };
                                client.send_packet(&packet);
                            }
                        }
                    }
                    for deserialized_packet in message.packets {
                        client_connected
                            .bevy_caller
                            .client_call(&mut commands, deserialized_packet);
                    }

                    client.tick_after_message();
                }
                ClientTickResult::Disconnected => {
                    panic!(
                        "client disconnected: {:?}",
                        client.take_disconnect_reason().unwrap()
                    )
                }
                _ => (),
            }
        }
    }
}
