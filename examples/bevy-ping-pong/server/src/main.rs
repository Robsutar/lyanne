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
use lyanne::transport::server::{ReadHandlerProps, ServerRead};
use lyanne::{
    packets::{BarPacket, FooPacket, FooPacketServerSchedule, Packet, PacketRegistry},
    transport::server::{self, ServerMut, ServerShared},
};
use rand::{thread_rng, Rng};
use tokio::runtime::Runtime;

#[derive(Resource)]
struct X(Arc<Runtime>);

#[derive(Component)]
struct ServerConnecting {
    task: Task<Result<(Arc<ServerRead>, Arc<RwLock<ServerShared>>, ServerMut), io::Error>>,
}

#[derive(Component)]
struct ServerConnected {
    server_read: Arc<ServerRead>,
    server_shared: Arc<RwLock<ServerShared>>,
    server_mut: ServerMut,
    read_handler_props: Arc<ReadHandlerProps>,
}

#[derive(Resource)]
struct MyTimer(Timer);

fn main() {
    App::default()
        // Resources
        .insert_resource(MyTimer(Timer::from_seconds(0.5, TimerMode::Repeating)))
        // Plugins
        .add_plugins(TaskPoolPlugin::default())
        .add_plugins(TypeRegistrationPlugin::default())
        .add_plugins(FrameCountPlugin::default())
        .add_plugins(ScheduleRunnerPlugin::run_loop(Duration::from_millis(3)))
        .add_plugins(LogPlugin::default())
        .add_plugins(TimePlugin::default())
        .insert_resource(X(Arc::new(
            Runtime::new().expect("Failed to create Tokio runtime"),
        )))
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, server_tick)
        .add_systems(FooPacketServerSchedule, foo_read)
        .add_systems(BarPacketServerSchedule, bar_read)
        .add_systems(BarPacketServerSchedule, bar_second_read)
        .run();
}

fn init(mut commands: Commands, x: Res<X>) {
    let packet_registry = Arc::new(PacketRegistry::new());

    let task_pool = AsyncComputeTaskPool::get();

    let runtime = Arc::clone(&x.0);

    let task = task_pool.spawn(async move {
        runtime
            .spawn(
                async move { server::bind("127.0.0.1:8822", Arc::clone(&packet_registry)).await },
            )
            .await
            .unwrap()
    });

    commands.spawn(ServerConnecting { task });
}

fn foo_read(mut packet: ResMut<ServerPacketResource<FooPacket>>) {
    let packet = packet.packet.take();
    println!("xaxa! {:?}", packet);
}

fn bar_read(mut packet: ResMut<ServerPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    println!("pepe! {:?}", packet);
}

fn bar_second_read(mut packet: ResMut<ServerPacketResource<BarPacket>>) {
    let packet = packet.packet.take();
    println!("pepe TWO! {:?}", packet);
}

fn read_bind_result(
    mut commands: Commands,
    mut query: Query<(Entity, &mut ServerConnecting)>,
    x: Res<X>,
) {
    let runtime = Arc::clone(&x.0);
    for (entity, mut server_connecting) in query.iter_mut() {
        if let Some(bind) = future::block_on(future::poll_once(&mut server_connecting.task)) {
            commands.entity(entity).despawn();

            match bind {
                Ok((server_read, server_shared, server_mut)) => {
                    info!("Server bind");

                    let read_handler_props = Arc::new(ReadHandlerProps::default());
                    let runtime = Arc::clone(&runtime);

                    for _ in 0..read_handler_props.surplus_target_size {
                        server::add_read_handler(
                            Arc::clone(&server_read),
                            Arc::clone(&server_shared),
                            Arc::clone(&read_handler_props),
                            Arc::clone(&runtime),
                        );
                    }

                    commands.spawn(ServerConnected {
                        server_read,
                        server_shared,
                        server_mut,
                        read_handler_props,
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
    mut query: Query<&mut ServerConnected>,
    x: Res<X>,
    time: Res<Time>,
    mut my_timer: ResMut<MyTimer>,
) {
    if my_timer.0.tick(time.delta()).just_finished() {
        let task_pool = AsyncComputeTaskPool::get();
        for mut server_connected in query.iter_mut() {
            let runtime = Arc::clone(&x.0);
            let server_read = Arc::clone(&server_connected.server_read);
            let server_shared = Arc::clone(&server_connected.server_shared);
            let read_handler_props = Arc::clone(&server_connected.read_handler_props);

            {
                println!("sending(storing) some random packets");
                for (_, connected_client) in
                    server_connected.server_mut.connected_clients.iter_mut()
                {
                    let mut rng = thread_rng();
                    for _ in 0..rng.gen_range(0..2) {
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

            let mut clients_packets_to_process = server::tick(
                Arc::clone(&server_read),
                Arc::clone(&server_shared),
                &mut server_connected.server_mut,
                Arc::clone(&runtime),
            );

            for (addr, packets_to_process) in clients_packets_to_process.iter_mut() {
                while packets_to_process.len() > 0 {
                    let deserialized_packet = packets_to_process.remove(0);
                    server_read
                        .packet_registry
                        .bevy_server_call(&mut commands, deserialized_packet);
                }
            }

            task_pool
                .spawn(async move {
                    Arc::clone(&runtime).spawn({
                        async move {
                            if *read_handler_props.surplus_count.lock().await
                                < read_handler_props.surplus_target_size - 1
                            {
                                server::add_read_handler(
                                    Arc::clone(&server_read),
                                    Arc::clone(&server_shared),
                                    Arc::clone(&read_handler_props),
                                    Arc::clone(&runtime),
                                );
                            }
                        }
                    });
                })
                .detach();
        }
    }
}
