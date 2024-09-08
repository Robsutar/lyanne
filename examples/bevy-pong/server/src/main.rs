pub mod game;

use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};

use bevy::tasks::Task;
use bevy::time::TimePlugin;
use bevy::{app::ScheduleRunnerPlugin, log::LogPlugin, prelude::*, tasks::futures_lite::future};
use bevy_pong::{AuthenticationPacket, BevyPacketCaller, GameConfig, PacketManagers};
use lyanne::auth_tcp::AuthTcpServerProperties;
use lyanne::auth_tls::{AuthTlsServerProperties, CertKey, ServerCertProvider};
use lyanne::server::{AuthenticatorMode, Server};
use lyanne::server::{BindError, BindResult, ServerProperties};
use lyanne::{MessagingProperties, ReadHandlerProperties};

#[derive(Component)]
struct ServerConnecting {
    bevy_caller: Option<BevyPacketCaller>,
    task: Task<Result<BindResult, BindError>>,
}

#[derive(Component)]
struct ServerConnected {
    server: Option<Server>,
    bevy_caller: Option<BevyPacketCaller>,
    players: Vec<(SocketAddr, AuthenticationPacket)>,
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

    let authenticator_mode = {
        if true {
            AuthenticatorMode::RequireTcp(AuthTcpServerProperties {
                server_addr: "127.0.0.1:4443".parse().unwrap(),
            })
        } else if false {
            AuthenticatorMode::RequireTls(AuthTlsServerProperties {
                server_name: "localhost",
                server_addr: "127.0.0.1:4443".parse().unwrap(),
                server_cert: ServerCertProvider::SingleCert(
                    CertKey::from_file(
                        "examples/tls_certificates/server_cert.pem",
                        "examples/tls_certificates/server_key.pem",
                    )
                    .unwrap(),
                ),
            })
        } else {
            AuthenticatorMode::NoCryptography
        }
    };

    let bind_handle = Server::bind(
        addr,
        Arc::new(packet_managers.packet_registry),
        messaging_properties,
        read_handler_properties,
        server_properties,
        authenticator_mode,
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
                        players: Vec::new(),
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
            if server_connected.players.len() == 2 {
                let server = server_connected.server.take().unwrap();
                let bevy_caller = server_connected.bevy_caller.take().unwrap();

                let player_left = server_connected.players.remove(0);
                let player_right = server_connected.players.remove(0);

                commands.entity(entity).despawn();
                commands.spawn(game::Game::start(
                    GameConfig::default(),
                    server,
                    Arc::new(bevy_caller),
                    player_left.0,
                    player_left.1.player_name,
                    player_right.0,
                    player_right.1.player_name,
                ));
            } else {
                {
                    let tick_result = server_connected.server.as_ref().unwrap().tick_start();

                    let clients_to_auth = tick_result.to_auth;

                    for (addr, (addr_to_auth, message)) in clients_to_auth {
                        if let Ok(auth_packet) = message
                            .to_packet_list()
                            .remove(0)
                            .packet
                            .downcast::<AuthenticationPacket>()
                        {
                            info!(
                                "authenticating client {:?}, authentication packet: {:?}",
                                addr, auth_packet
                            );
                            server_connected.players.push((addr, *auth_packet));
                            server_connected.server.as_ref().unwrap().authenticate(
                                addr,
                                addr_to_auth,
                                server_connected
                                    .server
                                    .as_ref()
                                    .unwrap()
                                    .packet_registry()
                                    .empty_serialized_list(),
                            );

                            if server_connected.players.len() == 2 {
                                break;
                            }
                        }
                    }

                    for (addr, reason) in tick_result.disconnected {
                        info!("client disconnected: {:?}, reason: {:?}", addr, reason)
                    }

                    server_connected.server.as_ref().unwrap().tick_end();
                }
            }
        }
    }
}
