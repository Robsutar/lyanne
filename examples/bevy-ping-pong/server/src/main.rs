use std::{io, sync::Arc, time::Duration};

use bevy::time::TimePlugin;
use bevy::{
    app::ScheduleRunnerPlugin,
    log::LogPlugin,
    prelude::*,
    tasks::{futures_lite::future, AsyncComputeTaskPool, Task},
};
use bevy_ping_pong::{
    BarPacket, BarPacketServerSchedule, BevyPacketCaller, FooPacket, FooPacketServerSchedule,
    PacketManagers,
};
use lyanne::packets::{SerializedPacketList, ServerPacketResource};
use lyanne::rt::TaskHandle;
use lyanne::transport::server::Server;
use lyanne::transport::server::{BindResult, IgnoredAddrReason, ServerProperties};
use lyanne::transport::{MessagingProperties, ReadHandlerProperties};
use rand::{thread_rng, Rng};

#[derive(Component)]
struct ServerConnecting {
    bevy_caller: Option<BevyPacketCaller>,
    task: TaskHandle<io::Result<BindResult>>,
}

#[derive(Component)]
struct ServerConnected {
    server: Option<Server>,
    bevy_caller: BevyPacketCaller,
    tick_timer: Timer,
}

fn main() {
    App::default()
        // Plugins
        .add_plugins(TaskPoolPlugin::default())
        .add_plugins(TypeRegistrationPlugin::default())
        .add_plugins(FrameCountPlugin::default())
        .add_plugins(ScheduleRunnerPlugin::run_loop(Duration::from_millis(3)))
        .add_plugins(LogPlugin::default())
        .add_plugins(TimePlugin::default())
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, server_tick)
        .add_systems(FooPacketServerSchedule, foo_read)
        .add_systems(BarPacketServerSchedule, bar_read)
        .add_systems(BarPacketServerSchedule, bar_second_read)
        .run();
}

fn init(mut commands: Commands) {
    let addr = "127.0.0.1:8822".parse().unwrap();
    let packet_managers = PacketManagers::default();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let server_properties = Arc::new(ServerProperties::default());

    let bind_handle = Server::bind(
        addr,
        Arc::new(packet_managers.packet_registry),
        messaging_properties,
        read_handler_properties,
        server_properties,
    );

    commands.spawn(ServerConnecting {
        bevy_caller: Some(packet_managers.bevy_caller),
        task: bind_handle,
    });
}

fn foo_read(mut packet: ResMut<ServerPacketResource<FooPacket>>) {
    let packet = packet.packet.take();
    //println!("xaxa! {:?}", packet);
}

fn bar_read(mut packet: ResMut<ServerPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    //println!("pepe! {:?}", packet);
}

fn bar_second_read(mut packet: ResMut<ServerPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    //println!("pepe TWO! {:?}", packet);
}

fn read_bind_result(mut commands: Commands, mut query: Query<(Entity, &mut ServerConnecting)>) {
    for (entity, mut server_connecting) in query.iter_mut() {
        if let Some(bind) = future::block_on(future::poll_once(&mut server_connecting.task)) {
            commands.entity(entity).despawn();

            match bind {
                Ok(bind_result) => {
                    info!("Server bind");

                    if false {
                        bind_result.server.ignore_ip(
                            "127.0.0.1".parse().unwrap(),
                            IgnoredAddrReason::from_serialized_list(SerializedPacketList::create(
                                vec![bind_result.server.packet_registry().serialize(&FooPacket {
                                    message: "Oh no!".to_owned(),
                                })],
                            )),
                        );
                    }

                    commands.spawn(ServerConnected {
                        server: Some(bind_result.server),
                        tick_timer: Timer::from_seconds(0.05, TimerMode::Repeating),
                        bevy_caller: server_connecting.bevy_caller.take().unwrap(),
                    });
                }
                Err(err) => {
                    error!("Failed to bind server: {}", err);
                }
            }
        }
    }
}

fn server_tick(
    mut commands: Commands,
    mut query: Query<(Entity, &mut ServerConnected)>,
    time: Res<Time>,
) {
    for (entity, mut server_connected) in query.iter_mut() {
        if server_connected
            .tick_timer
            .tick(time.delta())
            .just_finished()
        {
            let server = server_connected.server.as_ref().unwrap();
            if true {
                for entry in server.connected_clients_iter() {
                    let connected_client = entry.value();
                    let mut rng = thread_rng();
                    for _ in 0..rng.gen_range(500..501) {
                        let message = format!("Random str: {:?}", rng.gen::<i32>());
                        if rng.gen_bool(0.5) {
                            let packet = FooPacket { message };
                            server.send_packet(&connected_client, &packet);
                        } else {
                            let packet = BarPacket { message };
                            server.send_packet(&connected_client, &packet);
                        }
                    }
                }
            }

            if false {
                let mut rng = thread_rng();
                if rng.gen_bool(0.01) {
                    info!("Disconnecting clients");
                    for client in server.connected_clients_iter() {
                        server.disconnect_from(
                            &client,
                            Some(SerializedPacketList::create(vec![server
                                .packet_registry()
                                .serialize(&BarPacket {
                                    message: "Bye bye".to_owned(),
                                })])),
                        )
                    }
                }
            }

            {
                let tick_result = server.tick_start();

                let clients_packets_to_process = tick_result.received_messages;
                let clients_to_auth = tick_result.to_auth;

                for (_, message_list) in clients_packets_to_process {
                    for message in message_list {
                        for deserialized_packet in message.packets {
                            server_connected
                                .bevy_caller
                                .server_call(&mut commands, deserialized_packet);
                        }
                    }
                }

                for (addr, message) in clients_to_auth {
                    if true {
                        info!(
                            "authenticating client {:?}, message count: {:?}",
                            addr,
                            message.message.len()
                        );
                        server.authenticate(addr, message);
                    } else {
                        info!(
                            "refusing client {:?}, message count: {:?}",
                            addr,
                            message.message.len()
                        );
                        server.refuse(
                            addr,
                            SerializedPacketList::create(vec![server.packet_registry().serialize(
                                &BarPacket {
                                    message: "No, you not".to_owned(),
                                },
                            )]),
                        );
                    }
                }

                for (addr, reason) in tick_result.disconnected {
                    info!("client disconnected: {:?}, reason: {:?}", addr, reason)
                }

                server.tick_end();
            }
        }
    }
}
