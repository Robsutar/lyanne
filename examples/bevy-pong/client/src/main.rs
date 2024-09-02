pub mod game;

use std::sync::Arc;
use std::time::Duration;

use bevy::tasks::Task;
use bevy::{prelude::*, tasks::futures_lite::future};
use bevy_pong::{AuthenticationPacket, BevyPacketCaller, GameStartPacket, PacketManagers};
use lyanne::auth_tcp::AuthTcpClientProperties;
use lyanne::auth_tls::{AuthTlsClientProperties, RootCertStoreProvider};
use lyanne::client::{
    AuthenticationProperties, AuthenticatorMode, Client, ClientTickResult, ConnectError,
    ConnectResult, ConnectedAuthenticatorMode,
};
use lyanne::{client::ClientProperties, packets::SerializedPacketList};
use lyanne::{MessagingProperties, ReadHandlerProperties};

#[derive(Component)]
struct ClientConnecting {
    bevy_caller: Option<BevyPacketCaller>,
    task: Task<Result<ConnectResult, ConnectError>>,
}

#[derive(Component)]
struct ClientConnected {
    client: Option<Client>,
    bevy_caller: Option<BevyPacketCaller>,
}

fn main() {
    App::default()
        // Plugins
        .add_plugins(DefaultPlugins)
        .add_plugins(game::GamePlugin)
        .add_systems(Startup, init)
        .add_systems(Update, read_bind_result)
        .add_systems(Update, client_tick)
        .run();
}

fn init(mut commands: Commands) {
    commands.spawn(Camera2dBundle::default());

    let remote_addr = "127.0.0.1:8822".parse().unwrap();
    let packet_managers = PacketManagers::default();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());

    let authenticator_mode = AuthenticatorMode::AttemptList(vec![
        AuthenticatorMode::RequireTls(
            AuthenticationProperties {
                message: SerializedPacketList::create(vec![packet_managers
                    .packet_registry
                    .serialize(&AuthenticationPacket {
                        player_name: my_name_of(&ConnectedAuthenticatorMode::RequireTls),
                    })]),
                timeout: Duration::from_secs(3),
            },
            AuthTlsClientProperties {
                server_name: "localhost",
                server_addr: "127.0.0.1:4443".parse().unwrap(),
                root_cert_store: RootCertStoreProvider::from_file(
                    "examples/tls_certificates/ca_cert.pem",
                )
                .unwrap(),
            },
        ),
        AuthenticatorMode::RequireTcp(
            AuthenticationProperties {
                message: SerializedPacketList::create(vec![packet_managers
                    .packet_registry
                    .serialize(&AuthenticationPacket {
                        player_name: my_name_of(&ConnectedAuthenticatorMode::RequireTcp),
                    })]),
                timeout: Duration::from_secs(3),
            },
            AuthTcpClientProperties {
                server_addr: "127.0.0.1:4443".parse().unwrap(),
            },
        ),
        AuthenticatorMode::NoCryptography(AuthenticationProperties {
            message: SerializedPacketList::create(vec![packet_managers.packet_registry.serialize(
                &AuthenticationPacket {
                    player_name: my_name_of(&ConnectedAuthenticatorMode::NoCryptography),
                },
            )]),
            timeout: Duration::from_secs(3),
        }),
    ]);

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_managers.packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
    );

    commands.spawn(ClientConnecting {
        bevy_caller: Some(packet_managers.bevy_caller),
        task: connect_handle,
    });
}

fn read_bind_result(mut commands: Commands, mut query: Query<(Entity, &mut ClientConnecting)>) {
    for (entity, mut client_connecting) in query.iter_mut() {
        if let Some(connect) = future::block_on(future::poll_once(&mut client_connecting.task)) {
            commands.entity(entity).despawn();

            match connect {
                Ok(connect_result) => {
                    let client_connected = ClientConnected {
                        client: Some(connect_result.client),
                        bevy_caller: Some(client_connecting.bevy_caller.take().unwrap()),
                    };
                    info!(
                        "Client connected, first message size: {:?}",
                        connect_result.message.as_packet_list().len()
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

fn client_tick(
    mut commands: Commands,
    mut query: Query<(Entity, &mut ClientConnected)>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<ColorMaterial>>,
) {
    'l1: for (entity, mut client_connected) in query.iter_mut() {
        let tick = client_connected.client.as_ref().unwrap().tick_start();
        match tick {
            ClientTickResult::ReceivedMessage(tick_result) => {
                for deserialized_packet in tick_result.message.to_packet_list() {
                    if let Ok(packet) = deserialized_packet.packet.downcast::<GameStartPacket>() {
                        commands.entity(entity).despawn();

                        let client = client_connected.client.take().unwrap();

                        client.tick_after_message();

                        let my_name = my_name_of(client.connected_server().auth_mode());

                        let game = game::Game::start(
                            packet.config,
                            &mut commands,
                            &mut meshes,
                            &mut materials,
                            client,
                            Arc::new(client_connected.bevy_caller.take().unwrap()),
                            packet.owned_type,
                            my_name,
                            packet.enemy_name,
                        );

                        commands.spawn(game);

                        continue 'l1;
                    }
                }

                client_connected
                    .client
                    .as_ref()
                    .unwrap()
                    .tick_after_message();
            }
            ClientTickResult::Disconnected => {
                panic!(
                    "client disconnected: {:?}",
                    client_connected
                        .client
                        .as_ref()
                        .unwrap()
                        .take_disconnect_reason()
                        .unwrap()
                )
            }
            _ => (),
        }
    }
}

#[cfg(not(feature = "player-2"))]
fn my_name() -> String {
    "Player 1".to_owned()
}
#[cfg(feature = "player-2")]
fn my_name() -> String {
    "Player 2".to_owned()
}

fn my_name_of(auth_mode: &ConnectedAuthenticatorMode) -> String {
    match auth_mode {
        ConnectedAuthenticatorMode::NoCryptography => format!("NOC-{}", my_name()),
        ConnectedAuthenticatorMode::RequireTcp => format!("TCP-{}", my_name()),
        ConnectedAuthenticatorMode::RequireTls => format!("TLS-{}", my_name()),
    }
}
