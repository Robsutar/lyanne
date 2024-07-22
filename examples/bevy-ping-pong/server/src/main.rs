pub mod game;

use std::{io, sync::Arc, time::Duration};

use bevy::time::TimePlugin;
use bevy::{app::ScheduleRunnerPlugin, log::LogPlugin, prelude::*, tasks::futures_lite::future};
use bevy_ping_pong::{BevyPacketCaller, GameConfig, PacketManagers};
use lyanne::packets::SerializedPacketList;
use lyanne::rt::TaskHandle;
use lyanne::transport::server::Server;
use lyanne::transport::server::{BindResult, IgnoredAddrReason, ServerProperties};
use lyanne::transport::{MessagingProperties, ReadHandlerProperties};

#[derive(Component)]
struct ServerConnecting {
    bevy_caller: Option<BevyPacketCaller>,
    task: TaskHandle<io::Result<BindResult>>,
}

#[derive(Component)]
struct ServerConnected {
    server: Option<Server>,
    bevy_caller: Option<BevyPacketCaller>,
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
        .add_plugins(game::GamePlugin)
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, server_tick)
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

fn read_bind_result(mut commands: Commands, mut query: Query<(Entity, &mut ServerConnecting)>) {
    for (entity, mut server_connecting) in query.iter_mut() {
        if let Some(bind) = future::block_on(future::poll_once(&mut server_connecting.task)) {
            commands.entity(entity).despawn();

            match bind {
                Ok(bind_result) => {
                    info!("Server bind");

                    commands.spawn(ServerConnected {
                        server: Some(bind_result.server),
                        bevy_caller: Some(server_connecting.bevy_caller.take().unwrap()),
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
            if server_connected
                .server
                .as_ref()
                .unwrap()
                .connected_clients_size()
                == 2
            {
                let mut connected_clients_iter = server_connected
                    .server
                    .as_ref()
                    .unwrap()
                    .connected_clients_iter();

                let player_left_addr = connected_clients_iter.next().unwrap().key().clone();
                let player_right_addr = connected_clients_iter.next().unwrap().key().clone();
                drop(connected_clients_iter);

                let server = server_connected.server.take().unwrap();
                let bevy_caller = server_connected.bevy_caller.take().unwrap();

                commands.entity(entity).despawn();
                commands.spawn(game::Game::start(
                    GameConfig::default(),
                    server,
                    Arc::new(bevy_caller),
                    player_left_addr,
                    "Player Left".to_owned(),
                    player_right_addr,
                    "Player Right".to_owned(),
                ));
            } else {
                let server = server_connected.server.as_ref().unwrap();

                {
                    let tick_result = server.tick_start();

                    let clients_to_auth = tick_result.to_auth;

                    for (addr, message) in clients_to_auth {
                        info!(
                            "authenticating client {:?}, message count: {:?}",
                            addr,
                            message.message.len()
                        );
                        server.authenticate(addr, message);
                    }

                    for (addr, reason) in tick_result.disconnected {
                        info!("client disconnected: {:?}, reason: {:?}", addr, reason)
                    }

                    server.tick_end();
                }
            }
        }
    }
}
