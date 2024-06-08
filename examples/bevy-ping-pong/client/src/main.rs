use std::sync::RwLock;
use std::{io, sync::Arc, time::Duration};

use bevy::{
    app::ScheduleRunnerPlugin,
    log::LogPlugin,
    prelude::*,
    tasks::{futures_lite::future, AsyncComputeTaskPool, Task},
};
use lyanne::packets::{BarPacketClientSchedule, ClientPacketResource};
use lyanne::transport::client::{ClientAsync, ClientRead, ClientTickResult, ConnectResult};
use lyanne::transport::MessagingProperties;
use lyanne::{
    packets::{BarPacket, FooPacket, FooPacketClientSchedule, PacketRegistry},
    transport::client::{self, ClientMut},
};
use rand::{thread_rng, Rng};
use tokio::runtime::Runtime;

#[derive(Component)]
struct ClientConnecting {
    task: Task<Result<ConnectResult, io::Error>>,
}

#[derive(Component)]
struct ClientConnected {
    client_read: Arc<ClientRead>,
    client_async: Arc<RwLock<ClientAsync>>,
    client_mut: ClientMut,
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
    let task_pool = AsyncComputeTaskPool::get();
    let runtime = Arc::new(Runtime::new().expect("Failed to create Tokio runtime"));

    let remote_addr = "127.0.0.1:8822".parse().unwrap();
    let packet_registry = Arc::new(PacketRegistry::new());
    let messaging_properties = Arc::new(MessagingProperties::default());

    let authentication_packets = vec![packet_registry
        .serialize(&FooPacket {
            message: "Auth me!!!".to_string(),
        })
        .unwrap()];

    let task = task_pool.spawn(async move {
        Arc::clone(&runtime)
            .spawn(async move {
                client::connect(
                    remote_addr,
                    packet_registry,
                    messaging_properties,
                    runtime,
                    authentication_packets,
                )
                .await
            })
            .await
            .unwrap()
    });

    commands.spawn(ClientConnecting { task });
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
                    info!("Client connected");

                    commands.spawn(ClientConnected {
                        client_read: connect_result.client_read,
                        client_async: connect_result.client_async,
                        client_mut: connect_result.client_mut,
                    });
                }
                Err(err) => {
                    error!("Failed to bind client: {}", err);
                }
            }
        }
    }
}

fn client_tick(mut commands: Commands, mut query: Query<&mut ClientConnected>) {
    for mut client_connected in query.iter_mut() {
        let client_read = Arc::clone(&client_connected.client_read);
        if let Ok(client_async_write) = Arc::clone(&client_connected.client_async).try_write() {
            let tick = client::tick(
                Arc::clone(&client_connected.client_read),
                Arc::clone(&client_connected.client_async),
                client_async_write,
                &mut client_connected.client_mut,
            );
            match tick {
                ClientTickResult::ReceivedMessage(message) => {
                    if true {
                        let mut rng = thread_rng();
                        for _ in 0..rng.gen_range(70..71) {
                            let message = format!("Random str: {:?}", rng.gen::<i32>());
                            if rng.gen_bool(0.5) {
                                let packet = FooPacket { message };
                                client_connected
                                    .client_mut
                                    .connected_server
                                    .send(&client_read, &packet)
                                    .unwrap();
                            } else {
                                let packet = BarPacket { message };
                                client_connected
                                    .client_mut
                                    .connected_server
                                    .send(&client_read, &packet)
                                    .unwrap();
                            }
                        }
                    }
                    for deserialized_packet in message.packets {
                        client_connected
                            .client_read
                            .packet_registry
                            .bevy_client_call(&mut commands, deserialized_packet);
                    }
                }
                ClientTickResult::Disconnect(reason) => {
                    panic!("client disconnected: {:?}", reason)
                }
                result => {
                    print!("{:?}", result);
                }
            }
        } else if false {
            panic!("could not take client async write instantly");
        } else {
            if true {
                println!("  [LOCKED_ASYNC] ***** could not take client async write instantly, trying in next tick");
            }
        }
    }
}
