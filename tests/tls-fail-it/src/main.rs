use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

mod error;
mod packets;
use auth_tls::{AuthTlsClientProperties, AuthTlsServerProperties, RootCertStoreProvider};
use error::Errors;
use lyanne::{client::*, packets::*, server::*, *};
use packets::*;

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_TICK_DELAY: Duration = Duration::from_millis(50);

const CLIENT_NAME: &'static str = "Josh";

fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");
    async_std::task::block_on(async_main())
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
                // Here we use the default certificates (pointing to localhost)
                lyanne::auth_tls::CertKey::from_file(
                    "examples/tls_certificates/server_cert.pem",
                    "examples/tls_certificates/server_key.pem",
                )
                .unwrap(),
            ),
        });

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

    let _server_handle = async_std::task::spawn(server_tick_cycle(server));

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
            // Here we use an alternative certificate (pointing to another dns)
            root_cert_store: RootCertStoreProvider::from_file(
                "examples/tls_certificates/alt/ca_cert.pem",
            )
            .unwrap(),
        },
    );

    let connect_handle = Client::connect(
        addr,
        packet_registry,
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
    );

    match connect_handle.await {
        Ok(_) => {
            return Err(Box::new(Errors::UnexpectedConnectResult));
        }
        Err(ConnectError::AuthenticatorConnectIoError(e)) => {
            println!("[CLIENT] Expected AuthenticatorConnectIoError: {:?}", e);
            Ok(())
        }
        Err(e) => return Err(Box::new(Errors::UnexpectedConnectError(e))),
    }
}

async fn server_tick_cycle(server: Server) {
    loop {
        let tick_result = server.tick_start();
        for (auth_entry, _) in tick_result.to_auth {
            panic!(
                "[SERVER] addr tried to authenticate {:?}",
                Errors::UnexpectedAddrToAuth(*auth_entry.addr())
            );
        }
        server.tick_end();
        futures_timer::Delay::new(SERVER_TICK_DELAY).await;
    }
}
