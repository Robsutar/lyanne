use bevy::time::TimePlugin;
use bevy::{app::ScheduleRunnerPlugin, log::LogPlugin, prelude::*, tasks::futures_lite::future};
use bevy_simple::packets::*;
use lyanne::{client::*, packets::*, *};
use rand::Rng;
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Component)]
struct ClientConnected {
    client: Client,
    tick_timer: Timer,
}

fn main() {
    App::default()
        .add_plugins(TaskPoolPlugin::default())
        .add_plugins(TypeRegistrationPlugin::default())
        .add_plugins(FrameCountPlugin::default())
        .add_plugins(ScheduleRunnerPlugin::run_loop(Duration::from_millis(3)))
        .add_plugins(LogPlugin::default())
        .add_plugins(TimePlugin::default())
        .add_systems(Startup, init)
        .add_systems(Update, server_tick)
        .run();
}

fn init(mut commands: Commands) {
    let packet_registry = new_packet_registry();

    let remote_addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography(AuthenticationProperties {
        message: SerializedPacketList::non_empty(vec![packet_registry.serialize(&HelloPacket {
            player_name: "Josh".to_owned(),
        })]),
        timeout: Duration::from_secs(10),
    });

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
    );

    let client = future::block_on(async {
        let connect_result = connect_handle.await;

        connect_result.expect("Failed to connect client").client
    });

    println!("Client connected to {:?}", remote_addr);

    commands.spawn(ClientConnected {
        client,
        tick_timer: Timer::new(Duration::from_millis(25), TimerMode::Repeating),
    });
}

fn server_tick(mut query: Query<&mut ClientConnected>, time: Res<Time>) {
    for mut client_connected in query.iter_mut() {
        if client_connected
            .tick_timer
            .tick(time.delta())
            .just_finished()
        {
            let client = &client_connected.client;
            match client.tick_start() {
                ClientTickResult::ReceivedMessage(tick_result) => {
                    use_tick_result(&client, tick_result);
                    inside_tick(&client);

                    client.tick_after_message();
                }
                ClientTickResult::Disconnected => {
                    println!(
                        "Client disconnected, reason: {:?}",
                        client.take_disconnect_reason().unwrap()
                    );
                    std::process::exit(0);
                }
                _ => (),
            }
        }
    }
}

fn use_tick_result(_client: &Client, tick_result: ReceivedMessageClientTickResult) {
    let message = tick_result.message.to_packet_list();
    for deserialized_packet in message {
        if let Ok(message_packet) = deserialized_packet.packet.downcast::<MessagePacket>() {
            println!("Server message: {:?}", message_packet.message);
        }
    }
}

fn inside_tick(client: &Client) {
    let packet = MessagePacket {
        message: "Bar?".to_owned(),
    };

    if rand::thread_rng().gen_bool(0.1) {
        client.send_packet(&packet);
    }
}
