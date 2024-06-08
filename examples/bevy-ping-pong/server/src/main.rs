use std::sync::RwLock;
use std::{io, sync::Arc, time::Duration};

use bevy::time::TimePlugin;
use bevy::{
    app::ScheduleRunnerPlugin,
    log::LogPlugin,
    prelude::*,
    tasks::{futures_lite::future, AsyncComputeTaskPool, Task},
};
use lyanne::packets::{BarPacketServerSchedule, ServerPacketResource};
use lyanne::transport::server::{BindResult, ReadHandlerProperties, ServerRead};
use lyanne::transport::MessagingProperties;
use lyanne::{
    packets::{BarPacket, FooPacket, FooPacketServerSchedule, PacketRegistry},
    transport::server::{self, ServerAsync, ServerMut},
};
use rand::{thread_rng, Rng};
use tokio::runtime::Runtime;

#[derive(Component)]
struct ServerConnecting {
    task: Task<Result<BindResult, io::Error>>,
}

#[derive(Component)]
struct ServerConnected {
    server_read: Arc<ServerRead>,
    server_async: Arc<RwLock<ServerAsync>>,
    server_mut: ServerMut,
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
    let task_pool = AsyncComputeTaskPool::get();
    let runtime = Arc::new(Runtime::new().expect("Failed to create Tokio runtime"));

    let addr = "127.0.0.1:8822".parse().unwrap();
    let packet_registry = Arc::new(PacketRegistry::new());
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());

    let task = task_pool.spawn(async move {
        Arc::clone(&runtime)
            .spawn(async move {
                server::bind(
                    addr,
                    packet_registry,
                    messaging_properties,
                    read_handler_properties,
                    runtime,
                )
                .await
            })
            .await
            .unwrap()
    });

    commands.spawn(ServerConnecting { task });
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

                    commands.spawn(ServerConnected {
                        server_read: bind_result.server_read,
                        server_async: bind_result.server_async,
                        server_mut: bind_result.server_mut,
                        tick_timer: Timer::from_seconds(0.05, TimerMode::Repeating),
                    });
                }
                Err(err) => {
                    error!("Failed to bind server: {}", err);
                }
            }
        }
    }
}

fn server_tick(mut commands: Commands, mut query: Query<&mut ServerConnected>, time: Res<Time>) {
    for mut server_connected in query.iter_mut() {
        let old_tick_timer = server_connected.tick_timer.clone();
        if server_connected
            .tick_timer
            .tick(time.delta())
            .just_finished()
        {
            if let Ok(server_async_write) = Arc::clone(&server_connected.server_async).try_write() {
                let server_read = Arc::clone(&server_connected.server_read);
                let server_async = Arc::clone(&server_connected.server_async);

                if true {
                    for (_, connected_client) in
                        server_connected.server_mut.connected_clients.iter_mut()
                    {
                        let mut rng = thread_rng();
                        for _ in 0..rng.gen_range(40..51) {
                            let message = format!("Random str: {:?}", rng.gen::<i32>());
                            if rng.gen_bool(0.5) {
                                let packet = FooPacket { message };
                                connected_client.send(&server_read, &packet).unwrap();
                            } else {
                                let packet = BarPacket { message };
                                connected_client.send(&server_read, &packet).unwrap();
                            }
                        }
                    }
                }

                {
                    let tick_result = server::tick(
                        Arc::clone(&server_read),
                        Arc::clone(&server_async),
                        server_async_write,
                        &mut server_connected.server_mut,
                    );

                    let clients_packets_to_process = tick_result.received_messages;
                    let clients_to_auth = tick_result.clients_to_auth;

                    for (_, message) in clients_packets_to_process {
                        for deserialized_packet in message.packets {
                            server_read
                                .packet_registry
                                .bevy_server_call(&mut commands, deserialized_packet);
                        }
                    }

                    for (addr, message) in clients_to_auth {
                        info!(
                            "authenticating client {:?}, message count: {:?}",
                            addr,
                            message.packets.len()
                        );
                        server_connected.server_mut.set_authenticated(addr);
                    }
                }
            } else if false {
                panic!("could not take server async write instantly");
            } else {
                if true {
                    println!("could not take server async write instantly, trying in next tick");
                }
                server_connected.tick_timer = old_tick_timer;
            }
        }
    }
}
