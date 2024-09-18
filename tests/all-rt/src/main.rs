use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

pub mod client;
pub mod error;
pub mod packets;
pub mod server;

use error::Errors;
use lyanne::{client::*, packets::*, server::*, *};
use packets::*;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const SERVER_TICK_DELAY: Duration = Duration::from_millis(50);

pub const CLIENT_NAME: &'static str = "Josh";
pub const SERVER_NAME: &'static str = "Server";
pub const SERVER_TO_CLIENT_MESSAGE: &'static str = "success: true";
pub const CLIENT_TO_SERVER_MESSAGE: &'static str = "true: success";
pub const SERVER_DISCONNECT_INFO: &'static str = "all: done";

fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");
    smol::block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn Error>> {
    let packet_registry = Arc::new(new_packet_registry());
    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());

    let server_properties = Arc::new(ServerProperties::default());
    let authenticator_mode = lyanne::server::AuthenticatorMode::NoCryptography;

    let bind_handle = Server::bind(
        addr,
        Arc::clone(&packet_registry),
        Arc::clone(&messaging_properties),
        Arc::clone(&read_handler_properties),
        server_properties,
        authenticator_mode,
    );

    let server = match bind_handle.await {
        Ok(bind_result) => bind_result.server,
        Err(e) => return Err(Box::new(Errors::BindFail(e))),
    };

    let server_handle = smol::spawn(server::start_tick_cycle(server));

    let server_properties = Arc::new(ClientProperties::default());
    let authenticator_mode =
        lyanne::client::AuthenticatorMode::NoCryptography(AuthenticationProperties {
            message: LimitedMessage::new(SerializedPacketList::single(packet_registry.serialize(
                &HelloPacket {
                    name: CLIENT_NAME.to_owned(),
                },
            ))),
            timeout: TIMEOUT,
        });

    let connect_handle = Client::connect(
        addr,
        packet_registry,
        messaging_properties,
        read_handler_properties,
        server_properties,
        authenticator_mode,
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

    let client_handle = smol::spawn(client::start_tick_cycle(client));

    server_handle.await.unwrap();
    client_handle.await.unwrap();

    Ok(())
}
