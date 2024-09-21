// TODO: add timeout in server loops
// TODO: change ids of the errors

use std::{
    error::Error,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

mod error;
mod packets;

use auth_tcp::{AuthTcpClientProperties, AuthTcpServerProperties};
use error::Errors;
use lyanne::{client::*, packets::*, server::*, *};
use packets::*;

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_TICK_DELAY: Duration = Duration::from_millis(50);

const CLIENT_NAME: &'static str = "Josh";
const SERVER_NAME: &'static str = "Server";
const SERVER_TO_CLIENT_MESSAGE: &'static str = "success: true";
const CLIENT_TO_SERVER_MESSAGE: &'static str = "true: success";
const CLIENT_DISCONNECT_INFO: &'static str = "all: done";

fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");
    let start = Instant::now();
    println!("TEST START {:?}", start);

    let runtime = Arc::new(async_executor::Executor::new());
    let runtime_clone = Arc::clone(&runtime);
    let _handle = std::thread::spawn(move || {
        futures::executor::block_on(runtime_clone.run(futures::future::pending::<()>()));
    });

    let result = futures::executor::block_on(async_main(runtime));
    println!("TEST ELAPSED TIME: {:?}", Instant::now() - start);
    result
}

async fn async_main(runtime: Arc<async_executor::Executor<'static>>) -> Result<(), Box<dyn Error>> {
    let packet_registry = Arc::new(new_packet_registry());
    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let tcp_addr: SocketAddr = "127.0.0.1:4443".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());

    let server_properties = Arc::new(ServerProperties::default());
    let authenticator_mode =
        lyanne::server::AuthenticatorMode::RequireTcp(AuthTcpServerProperties {
            server_addr: tcp_addr,
        });

    let bind_handle = Server::bind(
        addr,
        Arc::clone(&packet_registry),
        Arc::clone(&messaging_properties),
        Arc::clone(&read_handler_properties),
        server_properties,
        authenticator_mode,
        Arc::clone(&runtime),
    );

    let server = match bind_handle.await {
        Ok(bind_result) => bind_result.server,
        Err(e) => return Err(Box::new(Errors::BindFail(e))),
    };

    let server_handle = runtime.spawn(server_tick_cycle(server));

    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = lyanne::client::AuthenticatorMode::RequireTcp(
        AuthenticationProperties {
            message: LimitedMessage::new(SerializedPacketList::single(packet_registry.serialize(
                &HelloPacket {
                    name: CLIENT_NAME.to_owned(),
                },
            ))),
            timeout: TIMEOUT,
        },
        AuthTcpClientProperties {
            server_addr: tcp_addr,
        },
    );

    let connect_handle = Client::connect(
        addr,
        packet_registry,
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
        Arc::clone(&runtime),
    );

    let client = match connect_handle.await {
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

    let client_handle = runtime.spawn(client_tick_cycle(client));

    server_handle.await.unwrap();
    client_handle.await.unwrap();

    Ok(())
}

async fn client_tick_cycle(client: Client) -> Result<(), Errors> {
    // 0 = pending receive from the server
    // 1 = pending send by the client
    // 2 = pending client disconnection
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
                        let disconnection = Some(client::GracefullyDisconnection {
                            message: LimitedMessage::new(SerializedPacketList::single(
                                client.packet_registry().serialize(&GoodbyePacket {
                                    info: CLIENT_DISCONNECT_INFO.to_owned(),
                                }),
                            )),
                            timeout: TIMEOUT,
                        });
                        client.disconnect(disconnection).await;

                        return Ok(());
                    }
                };
            }
            ClientTickResult::Disconnected => {
                return Err(Errors::ClientUnexpectedDisconnection);
            }
            _ => (),
        }

        futures_timer::Delay::new(SERVER_TICK_DELAY / 2).await;
    }
}

async fn server_tick_cycle(server: Server) -> Result<(), Errors> {
    // 0 = pending connect client and send message to it
    // 1 = pending message by client
    // 2 = pending disconnection by client
    let mut order_state = 0;
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
            1 => {
                for (_, messages) in tick_result.received_messages {
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
                                    order_state = 2;
                                }
                            } else {
                                return Err(Errors::InvalidPacketDowncast(27189));
                            }
                        }
                    }
                }
            }
            _ => {
                for (_, disconnect_reason) in tick_result.disconnected {
                    match disconnect_reason {
                        ClientDisconnectReason::DisconnectRequest(deserialized_message) => {
                            if let Ok(goodbye_packet) = deserialized_message
                                .to_packet_list()
                                .remove(0)
                                .packet
                                .downcast::<GoodbyePacket>()
                            {
                                if goodbye_packet.info != CLIENT_DISCONNECT_INFO {
                                    return Err(Errors::UnexpectedServerDisconnectInfo);
                                } else {
                                    return Ok(());
                                }
                            } else {
                                return Err(Errors::InvalidPacketDowncast(37816));
                            }
                        }
                        e => return Err(Errors::DisconnectionConfirmFailedByClient(e)),
                    }
                }
            }
        }
        server.tick_end();
        futures_timer::Delay::new(SERVER_TICK_DELAY).await;
    }
}
