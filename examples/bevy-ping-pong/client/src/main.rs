use std::sync::RwLock;
use std::{io, sync::Arc, time::Duration};

use bevy::{
    app::ScheduleRunnerPlugin,
    log::LogPlugin,
    prelude::*,
    tasks::{futures_lite::future, AsyncComputeTaskPool, Task},
};
use lyanne::packets::{BarPacketClientSchedule, ClientPacketResource};
use lyanne::transport::client::ClientRead;
use lyanne::{
    packets::{BarPacket, FooPacket, FooPacketClientSchedule, Packet, PacketRegistry},
    transport::client::{self, ClientMut},
};
use rand::{thread_rng, Rng};
use tokio::runtime::Runtime;
use tokio::time::timeout;

#[derive(Resource)]
struct X(Arc<Runtime>);

#[derive(Component)]
struct ClientConnecting {
    task: Task<Result<(Arc<ClientRead>, ClientMut), io::Error>>,
}

#[derive(Component)]
struct ClientConnected {
    client_read: Arc<ClientRead>,
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
        .insert_resource(X(Arc::new(
            Runtime::new().expect("Failed to create Tokio runtime"),
        )))
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, client_tick)
        .add_systems(FooPacketClientSchedule, foo_read)
        .add_systems(BarPacketClientSchedule, bar_read)
        .add_systems(BarPacketClientSchedule, bar_second_read)
        .run();
}

fn init(mut commands: Commands, x: Res<X>) {
    let packet_registry = Arc::new(PacketRegistry::new());

    let task_pool = AsyncComputeTaskPool::get();

    let runtime = Arc::clone(&x.0);

    let task = task_pool.spawn(async move {
        runtime
                .spawn(async move {
                    client::connect("127.0.0.1:8822", Arc::clone(&packet_registry)).await
                })
                .await
                .unwrap()
    });

    commands.spawn(ClientConnecting { task });
}

fn foo_read(mut packet: ResMut<ClientPacketResource<FooPacket>>) {
    let packet = packet.packet.take();
    println!("xaxa! {:?}", packet);
}

fn bar_read(mut packet: ResMut<ClientPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    println!("pepe! {:?}", packet);
}

fn bar_second_read(mut packet: ResMut<ClientPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    println!("pepe TWO! {:?}", packet);
}

fn read_bind_result(
    mut commands: Commands,
    mut query: Query<(Entity, &mut ClientConnecting)>,
    x: Res<X>,
) {
    let runtime = Arc::clone(&x.0);
    for (entity, mut client_connecting) in query.iter_mut() {
        if let Some(bind) = future::block_on(future::poll_once(&mut client_connecting.task)) {
            commands.entity(entity).despawn();

            match bind {
                Ok((client_read, client_mut)) => {
                    info!("Client connected");

                    let a_client_read = Arc::clone(&client_read);

                    runtime.spawn(async move {
                        let client_read = a_client_read;
                        loop {
                            match timeout(
                                Duration::from_secs(10),
                                client::pre_read_next_message(&client_read),
                            )
                            .await
                            {
                                Ok(buf) => {
                                    let buf = buf.unwrap();
                                    if true {
                                        let mut rng = thread_rng();
                                        if rng.gen_bool(0.1) {
                                            println!("  packets received from server: {:?}, but a packet loss will be simulated", buf.len());
                                            continue;
                                        }
                                    }

                                    client::read_next_message(
                                        Arc::clone(&client_read),
                                        buf,
                                    )
                                    .await;
                                    println!();
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    });

                    commands.spawn(ClientConnected {
                        client_read,
                        client_mut,
                    });
                }
                Err(err) => {
                    error!("Failed to bind client: {}", err);
                }
            }
        }
    }
}

fn client_tick(mut commands: Commands, mut query: Query<&mut ClientConnected>, x: Res<X>) {
    for mut client_connected in query.iter_mut() {
        let runtime = Arc::clone(&x.0);
        let client_read = Arc::clone(&client_connected.client_read);

        if let Ok(mut packets_to_process) = client::tick(
            Arc::clone(&client_read),
            &mut client_connected.client_mut,
            Arc::clone(&runtime),
        ) {
            {
                println!("sending(storing) some random packets");
                let mut rng = thread_rng();
                for _ in 0..rng.gen_range(0..2) {
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
            while packets_to_process.len() > 0 {
                let deserialized_packet = packets_to_process.remove(0);
                client_read
                    .packet_registry
                    .bevy_client_call(&mut commands, deserialized_packet);
            }
        }
    }
}
