use lyanne::{server::*, *};
use rand::Rng;
use smol_simple::packets::*;
use std::{net::SocketAddr, sync::Arc, time::Duration};

fn main() {
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

    let server = smol::block_on(async {
        let bind_result = bind_handle.await;

        bind_result.expect("Failed to bind server").server
    });

    println!("Server bind at {:?}", addr);

    loop {
        let tick_result = server.tick_start();

        use_tick_result(&server, tick_result);
        inside_tick(&server);

        server.tick_end();

        std::thread::sleep(Duration::from_millis(50));
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
