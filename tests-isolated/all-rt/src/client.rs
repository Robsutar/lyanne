use crate::{
    error::Errors, packets::*, CLIENT_NAME, CLIENT_TO_SERVER_MESSAGE, SERVER_DISCONNECT_INFO,
    SERVER_NAME, SERVER_TICK_DELAY, SERVER_TO_CLIENT_MESSAGE, TIMEOUT,
};
use lyanne::{client::*, packets::*, *};
use std::{net::SocketAddr, sync::Arc};

pub async fn create() -> Result<Client, Errors> {
    let packet_registry = new_packet_registry();

    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let server_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography(AuthenticationProperties {
        message: LimitedMessage::new(SerializedPacketList::single(packet_registry.serialize(
            &HelloPacket {
                name: CLIENT_NAME.to_owned(),
            },
        ))),
        timeout: TIMEOUT,
    });

    let connect_handle = Client::connect(
        addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        server_properties,
        authenticator_mode,
    );

    match connect_handle.await {
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
                    return Err(Errors::UnexpectedHelloPacketName(1873));
                } else {
                    return Ok(connect_result.client);
                }
            } else {
                return Err(Errors::InvalidPacketDowncast(126999));
            }
        }
        Err(e) => Err(Errors::ConnectFail(e)),
    }
}

pub async fn start_tick_cycle(client: Client) -> Result<(), Errors> {
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

        futures_timer::Delay::new(SERVER_TICK_DELAY / 2).await;
    }
}
