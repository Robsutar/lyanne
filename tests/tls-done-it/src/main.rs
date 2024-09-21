use std::{
    error::Error,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

mod error;
mod packets;

use auth_tls::{AuthTlsClientProperties, AuthTlsServerProperties, RootCertStoreProvider};
use error::Errors;
use lyanne::{client::*, packets::*, server::*, *};
use packets::*;

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_TICK_DELAY: Duration = Duration::from_millis(50);

const CLIENT_NAME: &'static str = "Josh";
const SERVER_NAME: &'static str = "Server";
const SERVER_TO_CLIENT_MESSAGE: &'static str = "success: true";
const CLIENT_TO_SERVER_MESSAGE: &'static str = "true: success";
const SERVER_DISCONNECT_INFO: &'static str = "all: done";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");
    let start = Instant::now();
    println!("TEST START {:?}", start);

    let result = async_main().await;
    println!("TEST ELAPSED TIME: {:?}", Instant::now() - start);
    result
}

async fn async_main() -> Result<(), Box<dyn Error>> {
    let packet_registry = Arc::new(new_packet_registry());
    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let tls_addr: SocketAddr = "127.0.0.1:4443".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());

    let server_properties = Arc::new(ServerProperties::default());
    let authenticator_mode =
        lyanne::server::AuthenticatorMode::RequireTls(AuthTlsServerProperties {
            server_name: "localhost",
            server_addr: tls_addr,
            server_cert: auth_tls::ServerCertProvider::SingleCert(
                lyanne::auth_tls::CertKey::from_file(
                    "examples/tls_certificates/server_cert.pem",
                    "examples/tls_certificates/server_key.pem",
                )
                .unwrap(),
            ),
        });
    let runtime = tokio::runtime::Handle::current();

    let bind_handle = Server::bind(
        addr,
        Arc::clone(&packet_registry),
        Arc::clone(&messaging_properties),
        Arc::clone(&read_handler_properties),
        server_properties,
        authenticator_mode,
        runtime,
    );

    let server = match bind_handle.await.unwrap() {
        Ok(bind_result) => bind_result.server,
        Err(e) => return Err(Box::new(Errors::BindFail(e))),
    };

    let server_handle = tokio::spawn(server_tick_cycle(server));

    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = lyanne::client::AuthenticatorMode::RequireTls(
        AuthenticationProperties {
            message: LimitedMessage::new(SerializedPacketList::single(packet_registry.serialize(
                &HelloPacket {
                    name: CLIENT_NAME.to_owned(),
                },
            ))),
            timeout: TIMEOUT,
        },
        AuthTlsClientProperties {
            server_name: "localhost",
            server_addr: tls_addr,
            root_cert_store: RootCertStoreProvider::from_file(
                "examples/tls_certificates/ca_cert.pem",
            )
            .unwrap(),
        },
    );
    let runtime = tokio::runtime::Handle::current();

    let connect_handle = Client::connect(
        addr,
        packet_registry,
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
        runtime,
    );

    let client = match connect_handle.await.unwrap() {
        Ok(connect_result) => {
            if let Ok(hello_packet) = connect_result
                .initial_message
                .to_packet_list()
                .remove(0)
                .packet
                .downcast::<HelloPacket>()
            {
                println!("[CLIENT] reading server name: {:?}", hello_packet.name);
                if hello_packet.name != SERVER_NAME {
                    return Err(Box::new(Errors::UnexpectedHelloPacketName(1873)));
                } else {
                    connect_result.client
                }
            } else {
                return Err(Box::new(Errors::InvalidPacketDowncast(126999)));
            }
        }
        Err(e) => return Err(Box::new(Errors::ConnectFail(e))),
    };

    let client_handle = tokio::spawn(client_tick_cycle(client));

    server_handle.await.unwrap().unwrap();
    client_handle.await.unwrap().unwrap();

    Ok(())
}

async fn client_tick_cycle(client: Client) -> Result<(), Errors> {
    // 0 = pending receive from the server
    // 1 = pending send by the client
    // 2 = waiting server disconnection
    let mut order_state = 0;
    loop {
        match client.tick_start() {
            ClientTickResult::ReceivedMessage(tick_result) => {
                match order_state {
                    0 => {
                        if let Ok(message_packet) = tick_result
                            .message
                            .to_packet_list()
                            .remove(0)
                            .packet
                            .downcast::<MessagePacket>()
                        {
                            println!("[CLIENT] message: {:?}", message_packet.message);

                            if message_packet.message != SERVER_TO_CLIENT_MESSAGE {
                                return Err(Errors::UnexpectedMessageContent(1212));
                            } else {
                                order_state = 1;
                                client.tick_after_message();
                            }
                        } else {
                            return Err(Errors::InvalidPacketDowncast(81275));
                        }
                    }
                    1 => {
                        println!("[CLIENT] sending client message...");
                        client.send_packet(&MessagePacket {
                            message: CLIENT_TO_SERVER_MESSAGE.to_owned(),
                        });
                        order_state = 2;
                        client.tick_after_message();
                    }
                    _ => {
                        return Err(Errors::ServerShouldBeDisconnected);
                    }
                };
            }
            ClientTickResult::Disconnected => {
                if order_state == 2 {
                    println!("[CLIENT] received disconnection...");

                    let disconnect_reason = client.take_disconnect_reason().unwrap();
                    drop(client);
                    match disconnect_reason {
                        ServerDisconnectReason::DisconnectRequest(deserialized_message) => {
                            if let Ok(goodbye_packet) = deserialized_message
                                .to_packet_list()
                                .remove(0)
                                .packet
                                .downcast::<GoodbyePacket>()
                            {
                                if goodbye_packet.info != SERVER_DISCONNECT_INFO {
                                    return Err(Errors::UnexpectedServerDisconnectInfo);
                                } else {
                                    return Ok(());
                                }
                            } else {
                                return Err(Errors::InvalidPacketDowncast(37816));
                            }
                        }
                        e => return Err(Errors::DisconnectionConfirmFailedByServer(e)),
                    }
                } else {
                    return Err(Errors::ClientUnexpectedDisconnection);
                }
            }
            _ => (),
        }

        tokio::time::sleep(SERVER_TICK_DELAY / 2).await;
    }
}

async fn server_tick_cycle(server: Server) -> Result<(), Errors> {
    // 0 = pending connect client and send message to it
    // 1 = pending message by client and server disconnection
    let mut order_state = 0;

    let start = Instant::now();
    loop {
        let tick_result = server.tick_start();

        match order_state {
            0 => {
                if tick_result.to_auth.len() > 1 {
                    return Err(Errors::AdditionalAuthentication);
                }

                for (auth_entry, message) in tick_result.to_auth {
                    if let Ok(hello_packet) = message
                        .to_packet_list()
                        .remove(0)
                        .packet
                        .downcast::<HelloPacket>()
                    {
                        if hello_packet.name != CLIENT_NAME {
                            return Err(Errors::UnexpectedHelloPacketName(17263));
                        }

                        let addr = *auth_entry.addr();

                        println!("[SERVER] Authenticating client {:?}...", addr);

                        server.authenticate(
                            auth_entry,
                            SerializedPacketList::single(server.packet_registry().serialize(
                                &HelloPacket {
                                    name: SERVER_NAME.to_owned(),
                                },
                            )),
                        );

                        let client = server.get_connected_client(&addr).unwrap();

                        server.send_packet(
                            &client,
                            &MessagePacket {
                                message: SERVER_TO_CLIENT_MESSAGE.to_owned(),
                            },
                        );
                        order_state = 1;
                    } else {
                        return Err(Errors::InvalidPacketDowncast(392));
                    }
                }
            }
            _ => {
                for (addr, messages) in tick_result.received_messages {
                    for message in messages {
                        let mut packet_list = message.to_packet_list();
                        if packet_list.len() == 2 {
                            if let Ok(message_packet) =
                                packet_list.remove(0).packet.downcast::<MessagePacket>()
                            {
                                println!("[SERVER] Reading message: {:?}", message_packet.message);
                                if message_packet.message != CLIENT_TO_SERVER_MESSAGE {
                                    return Err(Errors::UnexpectedMessageContent(8734));
                                } else {
                                    let disconnection = Some(server::GracefullyDisconnection {
                                        timeout: TIMEOUT,
                                        message: LimitedMessage::new(SerializedPacketList::single(
                                            server.packet_registry().serialize(&GoodbyePacket {
                                                info: SERVER_DISCONNECT_INFO.to_owned(),
                                            }),
                                        )),
                                    });
                                    match server.disconnect(disconnection).await.unwrap() {
                                        ServerDisconnectState::Confirmations(mut hash_map) => {
                                            if let Some(disconnect_state) = hash_map.remove(&addr) {
                                                match disconnect_state {
                                                    ServerDisconnectClientState::Confirmed => {
                                                        return Ok(());
                                                    }
                                                    e => {
                                                        return Err(
                                                        Errors::DisconnectionConfirmFailedByClient(
                                                            e,
                                                        ),
                                                    );
                                                    }
                                                }
                                            } else {
                                                return Err(Errors::UnexpectedBehavior(1273));
                                            }
                                        }
                                        ServerDisconnectState::WithoutReason => {
                                            return Err(Errors::UnexpectedBehavior(4621))
                                        }
                                    }
                                }
                            } else {
                                return Err(Errors::InvalidPacketDowncast(27189));
                            }
                        }
                    }
                }
            }
        }
        server.tick_end();
        tokio::time::sleep(SERVER_TICK_DELAY).await;

        if Instant::now() - start > TIMEOUT {
            return Err(Errors::TimedOut);
        }
    }
}
