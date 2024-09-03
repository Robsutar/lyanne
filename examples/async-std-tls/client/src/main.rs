use async_std_tls::packets::*;
use lyanne::{client::*, packets::*, *};
use rand::Rng;
use std::{net::SocketAddr, sync::Arc, time::Duration};

fn main() {
    let packet_registry = new_packet_registry();

    let remote_addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = AuthenticatorMode::RequireTls(
        AuthenticationProperties {
            message: SerializedPacketList::create(vec![packet_registry.serialize(&HelloPacket {
                player_name: "Josh".to_owned(),
            })]),
            timeout: Duration::from_secs(10),
        },
        lyanne::auth_tls::AuthTlsClientProperties {
            server_name: "localhost",
            server_addr: "127.0.0.1:4443".parse().unwrap(),
            root_cert_store: lyanne::auth_tls::RootCertStoreProvider::from_file(
                "examples/tls_certificates/ca_cert.pem",
            )
            .unwrap(),
        },
    );

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
    );

    let client = async_std::task::block_on(async {
        let connect_result = connect_handle.await;

        connect_result.expect("Failed to connect client").client
    });

    println!("Client connected to {:?}", remote_addr);

    loop {
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

        std::thread::sleep(Duration::from_millis(50));
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
