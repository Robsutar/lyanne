use lyanne::{server::*, *};
use packets::SerializedPacketList;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::runtime::Handle;
use tokio_chat::packets::*;

struct ClientRegistry {
    names_from_addrs: HashMap<SocketAddr, String>,
    addrs_from_names: HashMap<String, SocketAddr>,
}

#[tokio::main]
async fn main() {
    let runtime = Handle::current();

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
        runtime,
    );

    let bind_result = bind_handle.await.unwrap();

    let server = bind_result.expect("Failed to bind server").server;

    println!("Server bind at {:?}", addr);

    let mut client_registry = ClientRegistry {
        names_from_addrs: HashMap::new(),
        addrs_from_names: HashMap::new(),
    };

    loop {
        let tick_result = server.tick_start();

        use_tick_result(&server, tick_result, &mut client_registry);

        server.tick_end();

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn use_tick_result(
    server: &Server,
    tick_result: ServerTickResult,
    client_registry: &mut ClientRegistry,
) {
    for (addr, (addr_to_auth, message)) in tick_result.to_auth {
        if let Ok(hello_packet) = message
            .to_packet_list()
            .remove(0)
            .packet
            .downcast::<HelloPacket>()
        {
            if client_registry
                .addrs_from_names
                .contains_key(&hello_packet.player_name)
            {
                broadcast(
                    &server,
                    format!("Another {} entered the chat, but a {} is already connected to the server..", 
                        hello_packet.player_name, hello_packet.player_name),
                );

                server.refuse(
                    addr,
                    SerializedPacketList::create(vec![server.packet_registry().serialize(
                        &AuthenticationFailedPacket {
                            justification: format!(
                                "Another {} is already connected",
                                hello_packet.player_name
                            ),
                        },
                    )]),
                )
            } else {
                broadcast(
                    &server,
                    format!("{} entered the chat.", hello_packet.player_name),
                );

                server.authenticate(addr, addr_to_auth);
                client_registry
                    .names_from_addrs
                    .insert(addr, hello_packet.player_name.clone());
                client_registry
                    .addrs_from_names
                    .insert(hello_packet.player_name, addr);
            }
        } else {
            println!(
                "Client {:?} did not sent a `HelloPacket`, it will not be authenticated",
                addr
            );
        }
    }

    for (addr, reason) in tick_result.disconnected {
        let player_name = client_registry.names_from_addrs.remove(&addr).unwrap();
        let message = match reason {
            ClientDisconnectReason::DisconnectRequest(message) => {
                if let Ok(message_packet) = message
                    .to_packet_list()
                    .remove(0)
                    .packet
                    .downcast::<LeavePacket>()
                {
                    format!(
                        "{} left the chat, message: {:?}",
                        player_name, message_packet.message
                    )
                } else {
                    format!("{} left the chat (invalid message)", player_name)
                }
            }
            _ => format!("{} left the chat, reason: {:?}", player_name, reason),
        };
        broadcast(&server, message);
    }

    for (addr, messages) in tick_result.received_messages {
        let name = client_registry.names_from_addrs.get(&addr).unwrap();
        for message in messages {
            let packet_list = message.to_packet_list();
            for deserialized_packet in packet_list {
                if let Ok(message_packet) = deserialized_packet.packet.downcast::<MessagePacket>() {
                    broadcast(&server, format!("{}: {}", name, message_packet.message))
                }
            }
        }
    }

    let mut error_map = HashMap::<String, usize>::new();
    for error in tick_result.unexpected_errors {
        let debug = format!("{:?}", error);
        let entry = error_map.entry(debug).or_insert(0);
        *entry += 1;
    }
    if !error_map.is_empty() {
        println!("Errors: {:?}", error_map);
    }
}

fn broadcast(server: &Server, line: String) {
    println!("● {}", line);

    let packet = ChatLinePacket { line };

    for connected_client in server.connected_clients_iter() {
        server.send_packet(&connected_client, &packet);
    }
}
