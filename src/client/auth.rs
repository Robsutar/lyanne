use std::{
    collections::BTreeMap,
    fmt, io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{
    aead::AeadCore, aead::KeyInit, ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce,
};
use x25519_dalek::EphemeralSecret;

use crate::{
    messages::{DeserializedMessage, MessagePartMap},
    packets::{ClientTickEndPacket, PacketRegistry, SerializedPacketList},
    rt::{Mutex, UdpSocket},
    utils::{DurationMonitor, RttCalculator},
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::{MessageChannel, MessagingProperties, ReadHandlerProperties, MESSAGE_CHANNEL_SIZE};

use super::*;

#[cfg(feature = "auth_tcp")]
use crate::auth_tcp::AuthTcpClientProperties;

#[cfg(feature = "auth_tls")]
use crate::auth_tls::{AuthTlsClientProperties, TlsConnector};

#[cfg(feature = "auth_tls")]
use crate::auth_tls::rustls;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::rt::{AsyncReadExt, AsyncWriteExt, TcpStream};

/// Proprieties for handling the client authentication/handshake with the server.
pub struct AuthenticationProperties {
    /// The authentication message.
    pub message: SerializedPacketList,
    /// The timeout to wait for a server response.
    pub timeout: Duration,
}

/// Modes for exchanging keys between client and server.
///
/// This enum represents the different methods by which keys (e.g., Diffie-Hellman)
/// are exchanged for securing communication. Although communication is primarily
/// done using UDP, if a TCP or TLS authenticator is used, the Diffie-Hellman keys
/// are exchanged accordingly. These keys are then used for encrypting data throughout
/// the UDP connection.
pub enum AuthenticatorMode {
    /// No cryptographic exchange, using only the provided authentication properties.
    NoCryptography(AuthenticationProperties),
    /// Requires TCP-based key exchange for authentication.
    /// # Warning
    /// This authenticator alone is not responsible for encrypting the entire connection,
    /// the key exchange will be exposed if this TCP layer does not have a layer on top
    /// ensuring encryption, such as a reverse proxy.
    #[cfg(feature = "auth_tcp")]
    RequireTcp(AuthenticationProperties, AuthTcpClientProperties),
    /// Requires TLS-based key exchange for authentication.
    /// # Warning
    /// This authenticator uses `rustls` to cryptograph the key exchange between server and client.
    /// Ensure that the certificates provided in AuthTlsClientProperties are valid.
    #[cfg(feature = "auth_tls")]
    RequireTls(AuthenticationProperties, AuthTlsClientProperties),
    /// Attempts a list of authenticator modes in sequence until one succeeds.
    AttemptList(Vec<AuthenticatorMode>),
}

/// Connection mode between server and client.
///
/// See [`AuthenticatorMode`].
pub enum ConnectedAuthenticatorMode {
    NoCryptography,
    #[cfg(feature = "auth_tcp")]
    RequireTcp,
    #[cfg(feature = "auth_tls")]
    RequireTls,
}

/// Result when calling [`Client::connect`].
pub struct ConnectResult {
    /// Client used to manage the connection going forward.
    pub client: Client,
    /// Initial message sent by the server when accepting the connection of the client.
    pub initial_message: DeserializedMessage,
}

#[derive(Debug)]
pub struct DisconnectedConnectError {
    pub reason: ServerDisconnectReason,
    #[cfg(feature = "store_unexpected")]
    pub unexpected_errors: Vec<UnexpectedError>,
}

/// Possible reasons why a connection was unsuccessful with [`Client::connect`].
#[derive(Debug)]
pub enum ConnectError {
    /// Server took a long time to respond.
    Timeout,
    /// Server did not communicate correctly.
    InvalidProtocolCommunication,
    /// Invalid dns name.
    InvalidDnsName,
    /// Client addr is ignored by the server.
    Ignored(DeserializedMessage),
    /// IO error.
    IoError(io::Error),
    /// Client disconnected.
    Disconnected(DisconnectedConnectError),
    /// All attempts failed, see [`AuthenticatorMode::AttemptList`].
    AllAttemptsFailed(Vec<ConnectError>),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::Timeout => write!(f, "Server took a long time to respond."),
            ConnectError::InvalidProtocolCommunication => {
                write!(f, "Server did not communicate correctly.")
            }
            ConnectError::InvalidDnsName => write!(f, "Invalid dns name."),
            ConnectError::Ignored(message) => write!(
                f,
                "Client addr is ignored by the server, reason size: {}",
                message.as_packet_list().len()
            ),
            ConnectError::IoError(ref err) => write!(f, "IO error: {}", err),
            ConnectError::Disconnected(reason) => write!(f, "Client disconnected: {:?}", reason),
            Self::AllAttemptsFailed(errors) => write!(f, "All attempts failed: {:?}", errors),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ConnectError::IoError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ConnectError {
    fn from(error: io::Error) -> Self {
        ConnectError::IoError(error)
    }
}

pub(super) mod connecting {
    #[cfg(feature = "store_unexpected")]
    use client::store_unexpected_error_list_pick;

    use crate::messages::PUBLIC_KEY_SIZE;

    use super::*;

    pub async fn connect_auth_mode_match_arm(
        authenticator_mode: AuthenticatorMode,
        client_properties: &ClientProperties,
        socket: &UdpSocket,
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
    ) -> Result<(usize, SerializedPacketList, ConnectedAuthenticatorMode), ConnectError> {
        Ok(match authenticator_mode {
            AuthenticatorMode::NoCryptography(props) => {
                connect_no_cryptography_match_arm(&socket, buf, &public_key_sent, props).await?
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorMode::RequireTcp(props, auth_mode) => {
                connect_require_tcp_match_arm(buf, &public_key_sent, auth_mode, props).await?
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorMode::RequireTls(props, auth_mode) => {
                connect_require_tls_match_arm(buf, &public_key_sent, auth_mode, props).await?
            }
            AuthenticatorMode::AttemptList(modes) => {
                Box::pin(connect_attempt_list_match_arm(
                    &client_properties,
                    &socket,
                    buf,
                    &public_key_sent,
                    modes,
                ))
                .await?
            }
        })
    }

    pub async fn connect_no_cryptography_match_arm(
        socket: &UdpSocket,
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
        props: AuthenticationProperties,
    ) -> Result<(usize, SerializedPacketList, ConnectedAuthenticatorMode), ConnectError> {
        let sent_time = Instant::now();
        loop {
            let now = Instant::now();
            if now - sent_time > props.timeout {
                return Err(ConnectError::Timeout);
            }

            println!("sending {:?}", public_key_sent);
            socket.send(&public_key_sent).await?;
            match crate::rt::timeout(props.timeout, socket.recv(buf)).await {
                Ok(len) => {
                    let len = len?;
                    if len < MESSAGE_CHANNEL_SIZE {
                        return Err(ConnectError::InvalidProtocolCommunication);
                    }

                    match buf[0] {
                        MessageChannel::IGNORED_REASON => {
                            break Ok((
                                len,
                                props.message,
                                ConnectedAuthenticatorMode::NoCryptography,
                            ));
                        }
                        MessageChannel::PUBLIC_KEY_SEND => {
                            break Ok((
                                len,
                                props.message,
                                ConnectedAuthenticatorMode::NoCryptography,
                            ));
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }
    }

    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    pub async fn connect_require_tcp_based_match_arm<T>(
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
        mut stream: T,
    ) -> Result<usize, ConnectError>
    where
        T: AsyncReadExt,
        T: AsyncWriteExt,
        T: Unpin,
    {
        stream.write_all(&public_key_sent).await?;

        let len = match stream.read(buf).await {
            Ok(0) => return Err(ConnectError::InvalidProtocolCommunication),
            Ok(len) => len,
            Err(e) => {
                return Err(ConnectError::IoError(e));
            }
        };

        if len < MESSAGE_CHANNEL_SIZE {
            return Err(ConnectError::InvalidProtocolCommunication);
        }

        Ok(len)
    }

    #[cfg(feature = "auth_tcp")]
    pub async fn connect_require_tcp_match_arm(
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
        auth_mode: AuthTcpClientProperties,
        props: AuthenticationProperties,
    ) -> Result<(usize, SerializedPacketList, ConnectedAuthenticatorMode), ConnectError> {
        match crate::rt::timeout(props.timeout, async {
            let tcp_stream = TcpStream::connect(auth_mode.server_addr).await?;
            connect_require_tcp_based_match_arm(buf, public_key_sent, tcp_stream).await
        })
        .await
        {
            Ok(len) => Ok((len?, props.message, ConnectedAuthenticatorMode::RequireTcp)),
            Err(_) => return Err(ConnectError::Timeout),
        }
    }

    #[cfg(feature = "auth_tls")]
    pub async fn connect_require_tls_match_arm(
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
        auth_mode: AuthTlsClientProperties,
        props: AuthenticationProperties,
    ) -> Result<(usize, SerializedPacketList, ConnectedAuthenticatorMode), ConnectError> {
        match crate::rt::timeout(props.timeout, async {
            let server_name = match rustls::pki_types::ServerName::try_from(auth_mode.server_name) {
                Ok(server_name) => server_name,
                Err(_) => return Err(ConnectError::InvalidDnsName),
            };
            let config = Arc::new(auth_mode.new_client_config());
            let connector = TlsConnector::from(config);

            let stream = TcpStream::connect(auth_mode.server_addr).await?;
            let tls_stream = connector.connect(server_name, stream).await?;

            connect_require_tcp_based_match_arm(buf, public_key_sent, tls_stream).await
        })
        .await
        {
            Ok(len) => Ok((len?, props.message, ConnectedAuthenticatorMode::RequireTls)),
            Err(_) => return Err(ConnectError::Timeout),
        }
    }

    pub async fn connect_attempt_list_match_arm(
        client_properties: &ClientProperties,
        socket: &UdpSocket,
        buf: &mut [u8; 1024],
        public_key_sent: &Vec<u8>,
        modes: Vec<AuthenticatorMode>,
    ) -> Result<(usize, SerializedPacketList, ConnectedAuthenticatorMode), ConnectError> {
        let mut errors = Vec::<ConnectError>::new();
        for mode in modes {
            match connect_auth_mode_match_arm(
                mode,
                &client_properties,
                &socket,
                buf,
                &public_key_sent,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => errors.push(e),
            }
        }

        Err(ConnectError::AllAttemptsFailed(errors))
    }

    pub async fn connect_public_key_send_match_arm(
        socket: Arc<UdpSocket>,
        buf: [u8; 1024],
        _client_private_key: EphemeralSecret,
        message: SerializedPacketList,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        client_properties: Arc<ClientProperties>,
        task_runner: Arc<TaskRunner>,
        remote_addr: SocketAddr,
        connected_auth_mode: ConnectedAuthenticatorMode,
    ) -> Result<ConnectResult, ConnectError> {
        let mut server_public_key_bytes: [u8; PUBLIC_KEY_SIZE] = [0; PUBLIC_KEY_SIZE];
        server_public_key_bytes
            .copy_from_slice(&buf[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)]);

        let (authentication_bytes, inner_auth) = match &connected_auth_mode {
            &ConnectedAuthenticatorMode::NoCryptography => {
                let mut authentication_bytes = Vec::with_capacity(
                    MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE + message.bytes.len(),
                );
                authentication_bytes.push(MessageChannel::AUTH_MESSAGE);
                authentication_bytes.extend_from_slice(&server_public_key_bytes);
                authentication_bytes.extend(message.bytes);

                (authentication_bytes, InnerAuth::NoCryptography)
            }
            #[cfg(feature = "auth_tcp")]
            ConnectedAuthenticatorMode::RequireTcp => {
                let (cipher, authentication_bytes) =
                    connect_auth_cipher_arm(server_public_key_bytes, _client_private_key, message);
                (
                    authentication_bytes,
                    InnerAuth::RequireTcp(InnerAuthTcpBased { cipher }),
                )
            }
            #[cfg(feature = "auth_tls")]
            ConnectedAuthenticatorMode::RequireTls => {
                let (cipher, authentication_bytes) =
                    connect_auth_cipher_arm(server_public_key_bytes, _client_private_key, message);
                (
                    authentication_bytes,
                    InnerAuth::RequireTls(InnerAuthTcpBased { cipher }),
                )
            }
        };

        let (tasks_keeper_sender, tasks_keeper_receiver) = async_channel::unbounded();
        let (reason_to_disconnect_sender, reason_to_disconnect_receiver) =
            async_channel::bounded(1);

        let (receiving_bytes_sender, receiving_bytes_receiver) = async_channel::unbounded();
        let (packets_to_send_sender, packets_to_send_receiver) = async_channel::unbounded();
        let (message_part_confirmation_sender, message_part_confirmation_receiver) =
            async_channel::unbounded();
        let (shared_socket_bytes_send_sender, shared_socket_bytes_send_receiver) =
            async_channel::unbounded();

        let messaging = Mutex::new(ConnectedServerMessaging {
            inner_auth,
            pending_confirmation: BTreeMap::new(),
            incoming_messages: MessagePartMap::new(
                messaging_properties.initial_next_message_part_id,
            ),
            tick_bytes_len: 0,
            last_received_message_instant: Instant::now(),
            received_messages: Vec::new(),
            packet_loss_rtt_calculator: RttCalculator::new(messaging_properties.initial_latency),
            average_packet_loss_rtt: messaging_properties.initial_latency,
            latency_monitor: DurationMonitor::filled_with(messaging_properties.initial_latency, 16),
        });

        let server = Arc::new(ConnectedServer {
            receiving_bytes_sender,
            packets_to_send_sender,
            message_part_confirmation_sender,
            shared_socket_bytes_send_sender,
            addr: remote_addr,
            messaging,
            last_messaging_write: RwLock::new(Instant::now()),
            average_latency: RwLock::new(messaging_properties.initial_latency),
            incoming_messages_total_size: RwLock::new(0),
        });

        let tasks_keeper_handle =
            task_runner.spawn(client::create_async_tasks_keeper(tasks_keeper_receiver));
        let tasks_keeper_handle = Mutex::new(Some(tasks_keeper_handle));

        #[cfg(feature = "store_unexpected")]
        let (store_unexpected_errors, store_unexpected_errors_create_list_signal_receiver) =
            StoreUnexpectedErrors::new();

        let client = Client {
            internal: Arc::new(ClientInternal {
                tasks_keeper_sender,
                reason_to_disconnect_sender,
                reason_to_disconnect_receiver,
                #[cfg(feature = "store_unexpected")]
                store_unexpected_errors,

                authentication_mode: connected_auth_mode,

                tasks_keeper_handle,
                socket: Arc::clone(&socket),
                tick_state: RwLock::new(ClientTickState::TickStartPending),
                packet_registry: packet_registry.clone(),
                messaging_properties: Arc::clone(&messaging_properties),
                read_handler_properties: Arc::clone(&read_handler_properties),
                client_properties: Arc::clone(&client_properties),
                connected_server: Arc::clone(&server),
                disconnect_reason: RwLock::new(None),

                task_runner,
            }),
        };

        let internal = &client.internal;

        let tick_packet_serialized = packet_registry.serialize(&ClientTickEndPacket);

        let connected_server = &internal.connected_server;
        client.send_packet_serialized(tick_packet_serialized.clone());
        connected_server
            .packets_to_send_sender
            .try_send(None)
            .unwrap();

        let client_downgraded = Arc::downgrade(&internal);
        let server_downgraded = Arc::downgrade(&server);
        internal.create_async_task(async move {
            server::create_receiving_bytes_handler(
                client_downgraded,
                server_downgraded,
                receiving_bytes_receiver,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&internal);
        let server_downgraded = Arc::downgrade(&server);
        let initial_next_message_part_id =
            internal.messaging_properties.initial_next_message_part_id;
        internal.create_async_task(async move {
            server::create_packets_to_send_handler(
                client_downgraded,
                server_downgraded,
                packets_to_send_receiver,
                initial_next_message_part_id,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&internal);
        internal.create_async_task(async move {
            server::create_message_part_confirmation_handler(
                client_downgraded,
                message_part_confirmation_receiver,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&internal);
        internal.create_async_task(async move {
            server::create_shared_socket_bytes_send_handler(
                client_downgraded,
                shared_socket_bytes_send_receiver,
            )
            .await;
        });

        #[cfg(feature = "store_unexpected")]
        {
            let client_downgraded = Arc::downgrade(&internal);
            internal.create_async_task(async move {
                init::client::create_store_unexpected_error_list_handler(
                    client_downgraded,
                    store_unexpected_errors_create_list_signal_receiver,
                )
                .await;
            });
        }

        let sent_time = Instant::now();
        let mut last_sent_time = sent_time;
        let packet_loss_timeout = client_properties
            .auth_packet_loss_interpretation
            .min(messaging_properties.timeout_interpretation);

        loop {
            let a = client.tick_start();
            println!("a: {:?}", a);
            match a {
                ClientTickResult::ReceivedMessage(tick_result) => {
                    internal.try_check_read_handler();
                    client.tick_after_message();
                    return Ok(ConnectResult {
                        client,
                        initial_message: tick_result.message,
                    });
                }
                ClientTickResult::PendingMessage => (),
                ClientTickResult::Disconnected => {
                    #[cfg(feature = "store_unexpected")]
                    let unexpected_errors =
                        store_unexpected_error_list_pick(&client.internal).await;
                    return Err(ConnectError::Disconnected(DisconnectedConnectError {
                        reason: client.take_disconnect_reason().unwrap(),
                        #[cfg(feature = "store_unexpected")]
                        unexpected_errors,
                    }));
                }
                ClientTickResult::WriteLocked => (),
            }

            let now = Instant::now();
            if now - sent_time > messaging_properties.timeout_interpretation {
                return Err(ConnectError::Timeout);
            }

            if last_sent_time == sent_time || now - last_sent_time > packet_loss_timeout {
                last_sent_time = now;

                println!("send auti {:?}", authentication_bytes);
                socket.send(&authentication_bytes).await?;

                let pre_read_next_bytes_result =
                    ClientInternal::pre_read_next_bytes(&socket, packet_loss_timeout).await;

                match pre_read_next_bytes_result {
                    Ok(result) => {
                        let _read_result = internal.read_next_bytes(result).await;

                        println!("reas result {:?}", _read_result);

                        #[cfg(feature = "store_unexpected")]
                        if _read_result.is_unexpected() {
                            let _ = internal
                                .store_unexpected_errors
                                .error_sender
                                .send(UnexpectedError::OfReadServerBytes(_read_result))
                                .await;
                        }
                    }
                    Err(e) => {
                        println!("sending auti error {}", e);
                    }
                }
            }
        }
    }

    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    fn connect_auth_cipher_arm(
        server_public_key_bytes: [u8; 32],
        _client_private_key: EphemeralSecret,
        message: SerializedPacketList,
    ) -> (ChaCha20Poly1305, Vec<u8>) {
        let server_public_key = x25519_dalek::PublicKey::from(server_public_key_bytes);
        let shared_key = _client_private_key.diffie_hellman(&server_public_key);
        let cipher = ChaChaPoly1305::new(Key::from_slice(shared_key.as_bytes()));
        let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
        let cipher_bytes =
            SentMessagePart::cryptograph_message_part(&message.bytes, &cipher, &nonce);

        let mut authentication_bytes = Vec::with_capacity(
            MESSAGE_CHANNEL_SIZE
                + server_public_key_bytes.len()
                + nonce.len()
                + message.bytes.len(),
        );
        authentication_bytes.push(MessageChannel::AUTH_MESSAGE);
        authentication_bytes.extend_from_slice(&server_public_key_bytes);
        authentication_bytes.extend_from_slice(&nonce);
        authentication_bytes.extend(cipher_bytes);

        (cipher, authentication_bytes)
    }
}
