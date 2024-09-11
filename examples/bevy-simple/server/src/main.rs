use bevy::time::TimePlugin;
use bevy::{app::ScheduleRunnerPlugin, log::LogPlugin, prelude::*, tasks::futures_lite::future};
use bevy_simple::packets::*;
use lyanne::{server::*, *};
use rand::Rng;
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Component)]
struct ServerConnected {
    server: Server,
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

    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let server_properties = Arc::new(ServerProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography;

    let bind_handle = Server::bind(
        addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        server_properties,
        authenticator_mode,
    );

    let server = future::block_on(async {
        let bind_result = bind_handle.await;

        bind_result.expect("Failed to bind server").server
    });

    println!("Server bind at {:?}", addr);

    commands.spawn(ServerConnected {
        server,
        tick_timer: Timer::new(Duration::from_millis(50), TimerMode::Repeating),
    });
}

fn server_tick(mut query: Query<&mut ServerConnected>, time: Res<Time>) {
    for mut server_connected in query.iter_mut() {
        if server_connected
            .tick_timer
            .tick(time.delta())
            .just_finished()
        {
            let server = &server_connected.server;
            let tick_result = server.tick_start();

            use_tick_result(&server, tick_result);
            inside_tick(&server);

            server.tick_end();
        }
    }
}

fn use_tick_result(server: &Server, tick_result: ServerTickResult) {
    for (auth_entry, message) in tick_result.to_auth {
        if let Ok(hello_packet) = message
            .to_packet_list()
            .remove(0)
            .packet
            .downcast::<HelloPacket>()
        {
            println!(
                "Authenticating client {:?}, addr: {:?}",
                hello_packet.player_name, auth_entry.addr()
            );

            server.authenticate(
                auth_entry,
                server.packet_registry().empty_serialized_list(),
            );
        } else {
            println!(
                "Client {:?} did not sent a `HelloPacket`, it will not be authenticated",
                auth_entry.addr()
            );
        }
    }

    for (addr, reason) in tick_result.disconnected {
        println!("Client {:?} disconnected, reason: {:?}", addr, reason);
    }

    for (addr, messages) in tick_result.received_messages {
        for message in messages {
            let packet_list = message.to_packet_list();
            for deserialized_packet in packet_list {
                if let Ok(message_packet) = deserialized_packet.packet.downcast::<MessagePacket>() {
                    println!("Client {:?} message: {:?}", addr, message_packet.message);
                }
            }
        }
    }
}

fn inside_tick(server: &Server) {
    let packet = MessagePacket {
        message: "Foo!".to_owned(),
    };

    for client in server.connected_clients_iter() {
        if rand::thread_rng().gen_bool(0.1) {
            server.send_packet(&client, &packet);
        }
    }
}
