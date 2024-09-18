use crate::{
    error::Errors, packets::*, CLIENT_NAME, CLIENT_TO_SERVER_MESSAGE, SERVER_DISCONNECT_INFO,
    SERVER_NAME, SERVER_TICK_DELAY, SERVER_TO_CLIENT_MESSAGE, TIMEOUT,
};
use lyanne::{packets::*, server::*, *};
use std::{net::SocketAddr, sync::Arc};

pub async fn create() -> Result<Server, Errors> {
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

    match bind_handle.await {
        Ok(bind_result) => Ok(bind_result.server),
        Err(e) => Err(Errors::BindFail(e)),
    }
}

pub async fn start_tick_cycle(server: Server) -> Result<(), Errors> {
    // 0 = pending connect client and send message to it
    // 1 = pending message by client and server disconnection
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

                        server.send_packet(
                            server.get_connected_client(&addr).unwrap().value(),
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
                                    let disconnection = Some(GracefullyDisconnection {
                                        timeout: TIMEOUT,
                                        message: LimitedMessage::new(SerializedPacketList::single(
                                            server.packet_registry().serialize(&GoodbyePacket {
                                                info: SERVER_DISCONNECT_INFO.to_owned(),
                                            }),
                                        )),
                                    });
                                    match server.disconnect(disconnection).await {
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
        futures_timer::Delay::new(SERVER_TICK_DELAY).await;
    }
}
