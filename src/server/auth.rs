use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Instant,
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::ChaCha20Poly1305;
#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::Aead, Nonce};
use dashmap::{DashMap, DashSet};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::internal::messages::NONCE_SIZE;
use crate::internal::messages::{
    DeserializedMessage, MINIMAL_SERIALIZED_PACKET_SIZE, PUBLIC_KEY_SIZE,
};

use crate::MESSAGE_CHANNEL_SIZE;

use super::*;

#[cfg(feature = "auth_tcp")]
use crate::auth_tcp::AuthTcpServerProperties;

#[cfg(feature = "auth_tls")]
use crate::auth_tls::{AuthTlsServerProperties, TlsAcceptor, TlsStream};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::internal::rt::{AsyncReadExt, AsyncWriteExt, TcpListener, TcpStream};

/// Pending auth properties of a addr that is trying to connect.
pub(super) struct AddrPendingAuthSend {
    /// The instant that the request was received.
    pub received_time: Instant,
    /// Random private key created inside the server.
    #[allow(unused)]
    pub server_private_key: EphemeralSecret,
    /// Random public key created inside the server. Sent to the addr.
    pub server_public_key: PublicKey,
    /// Random public key created by the addr. Sent by the addr.
    #[allow(unused)]
    pub addr_public_key: PublicKey,
    /// Finished bytes, with the channel and the server public key.
    pub finished_bytes: Vec<u8>,
}

/// The holder to complete a connection with an Addr.
pub(super) struct AddrToAuth {
    pub inner_auth: InnerAuth,
}
pub(super) struct AuthMode {
    /// Set of addrs in the authentication process.
    pub addrs_in_auth: DashSet<SocketAddr>,
}

pub(super) trait AuthModeHandler {
    fn base(&self) -> &AuthMode;

    fn remove_from_auth(&self, addr: &SocketAddr) -> Option<SocketAddr> {
        self.base().addrs_in_auth.remove(addr)
    }

    fn tick_start(
        &self,
        internal: &ServerInternal,
        now: Instant,
        dispatched_assigned_addrs_in_auth: HashSet<SocketAddr>,
    ) {
        for addr in dispatched_assigned_addrs_in_auth {
            self.base().addrs_in_auth.remove(&addr).unwrap();
        }

        self.retain_pending_auth(internal, now);
    }

    fn retain_pending_auth(&self, internal: &ServerInternal, now: Instant);
    fn call_tick_start_signal(&self);
}

pub(super) struct NoCryptographyAuth {
    /// Sender for resending authentication bytes, like the server public key.
    pub pending_auth_resend_sender: async_channel::Sender<SocketAddr>,

    /// Map of pending authentication addresses.
    pub pending_auth: DashMap<SocketAddr, (AddrPendingAuthSend, Option<Instant>)>,

    pub base: AuthMode,
}
impl NoCryptographyAuth {
    async fn create_pending_auth_resend_handler(
        server: Weak<ServerInternal>,
        auth_mode: Weak<NoCryptographyAuth>,
        pending_auth_resend_receiver: async_channel::Receiver<SocketAddr>,
    ) {
        'l1: while let Ok(addr) = pending_auth_resend_receiver.recv().await {
            if let (Some(server), Some(auth_mode)) = (server.upgrade(), auth_mode.upgrade()) {
                if let Some(mut tuple) = auth_mode.pending_auth.get_mut(&addr) {
                    let (context, last_sent_time) = &mut *tuple;
                    *last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub(super) async fn read_next_bytes(
        internal: &ServerInternal,
        addr: SocketAddr,
        bytes: Vec<u8>,
        auth_mode: &NoCryptographyAuth,
    ) -> ReadClientBytesResult {
        let ip = addr.ip();
        if internal.ignored_ips.contains(&ip) {
            ReadClientBytesResult::IgnoredClientHandle
        } else if let Some(client) = internal.connected_clients.get(&addr) {
            let mut messaging = client.messaging.lock().await;
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 40;
            if messaging.tick_bytes_len > internal.messaging_properties.max_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.try_send(bytes);
                ReadClientBytesResult::ClientReceivedBytes
            }
        } else if auth_mode.base().addrs_in_auth.contains(&addr) {
            ReadClientBytesResult::AddrInAuth
        } else if bytes[0] == MessageChannel::AUTH_MESSAGE {
            if let Some((_, (pending_auth_send, _))) = auth_mode.pending_auth.remove(&addr) {
                if bytes.len()
                    < MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE + MINIMAL_SERIALIZED_PACKET_SIZE
                {
                    ReadClientBytesResult::AuthInsufficientBytesLen
                } else {
                    let message = DeserializedMessage::deserialize_single_list(
                        &bytes[(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)..],
                        &internal.packet_registry,
                    );
                    if let Ok(message) = message {
                        let mut sent_server_public_key: [u8; PUBLIC_KEY_SIZE] =
                            [0; PUBLIC_KEY_SIZE];
                        sent_server_public_key.copy_from_slice(
                            &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)],
                        );
                        let sent_server_public_key = PublicKey::from(sent_server_public_key);

                        if sent_server_public_key != pending_auth_send.server_public_key {
                            ReadClientBytesResult::InvalidPendingAuth
                        } else {
                            auth_mode.base().addrs_in_auth.insert(addr);

                            let _ = internal.clients_to_auth_sender.try_send((
                                addr,
                                (
                                    AddrToAuth {
                                        inner_auth: InnerAuth::NoCryptography,
                                    },
                                    message,
                                ),
                            ));
                            ReadClientBytesResult::DonePendingAuth
                        }
                    } else {
                        if let Some(punishment) =
                            internal.server_properties.invalid_message_punishment
                        {
                            internal.ignore_ip_temporary(ip, Instant::now() + punishment);
                        }
                        ReadClientBytesResult::InvalidPendingAuth
                    }
                }
            } else {
                ReadClientBytesResult::PendingPendingAuth
            }
        } else if bytes[0] == MessageChannel::PUBLIC_KEY_SEND
            && bytes.len() == (MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)
        {
            if auth_mode.pending_auth.len() >= internal.server_properties.max_pending_auth {
                return ReadClientBytesResult::PendingAuthFull;
            }

            let mut client_public_key: [u8; PUBLIC_KEY_SIZE] = [0; PUBLIC_KEY_SIZE];
            client_public_key.copy_from_slice(
                &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)],
            );
            let client_public_key = PublicKey::from(client_public_key);
            let server_private_key = EphemeralSecret::random_from_rng(OsRng);
            let server_public_key = PublicKey::from(&server_private_key);
            let server_public_key_bytes = server_public_key.as_bytes();

            let mut finished_bytes =
                Vec::with_capacity(MESSAGE_CHANNEL_SIZE + server_public_key_bytes.len());
            finished_bytes.push(MessageChannel::PUBLIC_KEY_SEND);
            finished_bytes.extend_from_slice(server_public_key_bytes);

            auth_mode.pending_auth.insert(
                addr,
                (
                    AddrPendingAuthSend {
                        received_time: Instant::now(),
                        server_private_key,
                        server_public_key,
                        addr_public_key: client_public_key,
                        finished_bytes,
                    },
                    None,
                ),
            );
            ReadClientBytesResult::PublicKeySend
        } else {
            ReadClientBytesResult::InvalidPublicKeySend(10)
        }
    }
}
impl AuthModeHandler for NoCryptographyAuth {
    fn base(&self) -> &AuthMode {
        &self.base
    }

    fn retain_pending_auth(&self, internal: &ServerInternal, now: Instant) {
        self.pending_auth.retain(|_, (pending_auth_send, _)| {
            now - pending_auth_send.received_time
                < internal.messaging_properties.timeout_interpretation
        });
        for tuple in self.pending_auth.iter() {
            let addr = tuple.key();
            let (_, last_sent_time) = tuple.value();
            if let Some(last_sent_time) = last_sent_time {
                if now - *last_sent_time
                    < internal
                        .server_properties
                        .pending_auth_packet_loss_interpretation
                {
                    continue;
                }
            }
            self.pending_auth_resend_sender.try_send(*addr).unwrap();
        }
    }

    fn call_tick_start_signal(&self) {}
}
pub(super) struct NoCryptographyAuthBuild {
    pending_auth_resend_receiver: async_channel::Receiver<SocketAddr>,
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub(super) struct RequireTcpBasedAuth {
    pub read_signal_sender: async_channel::Sender<()>,

    /// Map of pending authentication addresses.
    pub pending_auth: DashMap<PublicKey, AddrPendingAuthSend>,

    pub base: AuthMode,
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub(super) trait RequireTcpBasedAuthHandler<T>
where
    T: AsyncReadExt,
    T: AsyncWriteExt,
    T: Unpin,
{
    fn tcp_based_base(&self) -> &RequireTcpBasedAuth;

    async fn create_handler(
        auth_mode: Weak<Self>,
        server: Weak<ServerInternal>,
        listener: TcpListener,
        read_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = read_signal_receiver.recv().await {
            'l2: loop {
                if let (Some(server), Some(auth_mode)) = (server.upgrade(), auth_mode.upgrade()) {
                    let accepted = crate::internal::rt::timeout(
                        server.messaging_properties.timeout_interpretation,
                        listener.accept(),
                    )
                    .await;

                    if let Ok(accepted) = accepted {
                        if let Ok((stream, addr)) = accepted {
                            let _result = auth_mode.handler_accept(&server, addr, stream).await;

                            #[cfg(feature = "store_unexpected")]
                            match _result {
                                Ok(result) => {
                                    if result.is_unexpected() {
                                        let _ = server
                                            .store_unexpected_errors
                                            .error_sender
                                            .send(UnexpectedError::OfTcpBasedHandlerAccept(
                                                addr, result,
                                            ))
                                            .await;
                                    }
                                }
                                Err(e) => {
                                    let _ = server
                                        .store_unexpected_errors
                                        .error_sender
                                        .send(UnexpectedError::OfTcpBasedHandlerAcceptIoError(
                                            addr, e,
                                        ))
                                        .await;
                                }
                            }
                        }
                    } else {
                        break 'l2;
                    }
                } else {
                    break 'l1;
                }
            }
        }
    }

    async fn bound_stream(&self, raw_stream: TcpStream) -> io::Result<T>;

    async fn handler_accept(
        &self,
        internal: &ServerInternal,
        addr: SocketAddr,
        raw_stream: TcpStream,
    ) -> io::Result<ReadClientBytesResult> {
        let ip = addr.ip();

        if internal.ignored_ips.contains(&ip) {
            return Ok(ReadClientBytesResult::IgnoredClientHandle);
        } else if internal.connected_clients.contains_key(&addr) {
            return Ok(ReadClientBytesResult::AlreadyConnected);
        } else if self.tcp_based_base().base.addrs_in_auth.contains(&addr) {
            return Ok(ReadClientBytesResult::AddrInAuth);
        }

        let mut bound_stream = self.bound_stream(raw_stream).await?;

        let mut buf = [0u8; UDP_BUFFER_SIZE];

        let bytes = match bound_stream.read(&mut buf).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed by the client.",
                ));
            }
            Ok(n) => &buf[..n],
            Err(e) => {
                return Err(e);
            }
        };

        if bytes[0] == MessageChannel::PUBLIC_KEY_SEND
            && bytes.len() == (MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)
        {
            if self.tcp_based_base().pending_auth.len()
                >= internal.server_properties.max_pending_auth
            {
                return Ok(ReadClientBytesResult::PendingAuthFull);
            }

            let mut client_public_key: [u8; PUBLIC_KEY_SIZE] = [0; PUBLIC_KEY_SIZE];
            client_public_key.copy_from_slice(
                &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)],
            );
            let client_public_key = PublicKey::from(client_public_key);

            let mut server_private_key = EphemeralSecret::random_from_rng(OsRng);
            let mut server_public_key = PublicKey::from(&server_private_key);
            while self
                .tcp_based_base()
                .pending_auth
                .contains_key(&server_public_key)
            {
                server_private_key = EphemeralSecret::random_from_rng(OsRng);
                server_public_key = PublicKey::from(&server_private_key);
            }
            let server_public_key_bytes = server_public_key.as_bytes();

            let mut finished_bytes =
                Vec::with_capacity(MESSAGE_CHANNEL_SIZE + server_public_key_bytes.len());
            finished_bytes.push(MessageChannel::PUBLIC_KEY_SEND);
            finished_bytes.extend_from_slice(server_public_key_bytes);

            self.tcp_based_base().pending_auth.insert(
                server_public_key.clone(),
                AddrPendingAuthSend {
                    received_time: Instant::now(),
                    server_private_key,
                    server_public_key: server_public_key.clone(),
                    addr_public_key: client_public_key,
                    finished_bytes,
                },
            );

            let addr_pending_auth = self
                .tcp_based_base()
                .pending_auth
                .get(&server_public_key)
                .unwrap();
            bound_stream
                .write_all(&addr_pending_auth.finished_bytes)
                .await?;

            Ok(ReadClientBytesResult::PublicKeySend)
        } else {
            Ok(ReadClientBytesResult::InvalidPublicKeySend(20))
        }
    }

    fn inner_auth_of(&self, props: InnerAuthTcpBased) -> InnerAuth;

    async fn read_next_bytes(
        &self,
        internal: &ServerInternal,
        addr: SocketAddr,
        bytes: Vec<u8>,
    ) -> ReadClientBytesResult {
        let ip = addr.ip();

        if let Some(client) = internal.connected_clients.get(&addr) {
            let mut messaging = client.messaging.lock().await;
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 40;
            if messaging.tick_bytes_len > internal.messaging_properties.max_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.try_send(bytes);
                ReadClientBytesResult::ClientReceivedBytes
            }
        } else if self.tcp_based_base().base.addrs_in_auth.contains(&addr) {
            ReadClientBytesResult::AddrInAuth
        } else if bytes[0] == MessageChannel::AUTH_MESSAGE {
            if bytes.len() < MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE + MINIMAL_SERIALIZED_PACKET_SIZE
            {
                return ReadClientBytesResult::AuthInsufficientBytesLen;
            }

            let mut sent_server_public_key: [u8; PUBLIC_KEY_SIZE] = [0; PUBLIC_KEY_SIZE];
            sent_server_public_key.copy_from_slice(
                &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)],
            );
            let sent_server_public_key = PublicKey::from(sent_server_public_key);

            if let Some((_, pending_auth_send)) = self
                .tcp_based_base()
                .pending_auth
                .remove(&sent_server_public_key)
            {
                if bytes.len()
                    < MESSAGE_CHANNEL_SIZE
                        + PUBLIC_KEY_SIZE
                        + NONCE_SIZE
                        + MINIMAL_SERIALIZED_PACKET_SIZE
                {
                    ReadClientBytesResult::AuthInsufficientBytesLen
                } else {
                    let mut sent_server_public_key: [u8; PUBLIC_KEY_SIZE] = [0; PUBLIC_KEY_SIZE];
                    sent_server_public_key.copy_from_slice(
                        &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)],
                    );
                    let sent_server_public_key = PublicKey::from(sent_server_public_key);

                    if sent_server_public_key != pending_auth_send.server_public_key {
                        return ReadClientBytesResult::InvalidPendingAuth;
                    }

                    let shared_key = pending_auth_send
                        .server_private_key
                        .diffie_hellman(&pending_auth_send.addr_public_key);
                    let cipher: ChaCha20Poly1305 =
                        ChaChaPoly1305::new(Key::from_slice(shared_key.as_bytes()));

                    let nonce = Nonce::from_slice(
                        &bytes[(MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE)
                            ..((MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE) + NONCE_SIZE)],
                    );
                    let cipher_text =
                        &bytes[((MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE) + NONCE_SIZE)..];

                    let message_part_bytes = match cipher.decrypt(nonce, cipher_text) {
                        Ok(message_part_bytes) => message_part_bytes,
                        Err(_) => {
                            if let Some(punishment) =
                                internal.server_properties.invalid_message_punishment
                            {
                                internal.ignore_ip_temporary(ip, Instant::now() + punishment);
                            }
                            return ReadClientBytesResult::InvalidPendingAuth;
                        }
                    };

                    let message = DeserializedMessage::deserialize_single_list(
                        &message_part_bytes,
                        &internal.packet_registry,
                    );
                    if let Ok(message) = message {
                        self.tcp_based_base().base.addrs_in_auth.insert(addr);
                        let _ = internal.clients_to_auth_sender.try_send((
                            addr,
                            (
                                AddrToAuth {
                                    inner_auth: self.inner_auth_of(InnerAuthTcpBased { cipher }),
                                },
                                message,
                            ),
                        ));
                        ReadClientBytesResult::DonePendingAuth
                    } else {
                        if let Some(punishment) =
                            internal.server_properties.invalid_message_punishment
                        {
                            internal.ignore_ip_temporary(ip, Instant::now() + punishment);
                        }
                        ReadClientBytesResult::InvalidPendingAuth
                    }
                }
            } else {
                return ReadClientBytesResult::InvalidPendingAuth;
            }
        } else {
            ReadClientBytesResult::PendingPendingAuth
        }
    }
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
macro_rules! require_tcp_based_auth_handler_impl_for_auth_mode {
    () => {
        fn base(&self) -> &AuthMode {
            &self.tcp_based_base.base
        }

        fn retain_pending_auth(&self, internal: &ServerInternal, now: Instant) {
            self.tcp_based_base()
                .pending_auth
                .retain(|_, pending_auth_send| {
                    now - pending_auth_send.received_time
                        < internal.messaging_properties.timeout_interpretation
                });
        }

        fn call_tick_start_signal(&self) {
            let _ = self.tcp_based_base().read_signal_sender.try_send(());
        }
    };
}

#[cfg(feature = "auth_tcp")]
pub(super) struct RequireTcpAuth {
    pub properties: AuthTcpServerProperties,

    pub tcp_based_base: RequireTcpBasedAuth,
}
#[cfg(feature = "auth_tcp")]
impl RequireTcpBasedAuthHandler<TcpStream> for RequireTcpAuth {
    fn tcp_based_base(&self) -> &RequireTcpBasedAuth {
        &self.tcp_based_base
    }

    async fn bound_stream(&self, raw_stream: TcpStream) -> io::Result<TcpStream> {
        Ok(raw_stream)
    }

    fn inner_auth_of(&self, props: InnerAuthTcpBased) -> InnerAuth {
        InnerAuth::RequireTcp(props)
    }
}
#[cfg(feature = "auth_tcp")]
impl AuthModeHandler for RequireTcpAuth {
    require_tcp_based_auth_handler_impl_for_auth_mode!();
}
#[cfg(feature = "auth_tcp")]
pub(super) struct RequireTcpAuthBuild {
    tcp_read_signal_receiver: async_channel::Receiver<()>,
}

#[cfg(feature = "auth_tls")]
pub(super) struct RequireTlsAuth {
    pub properties: AuthTlsServerProperties,

    pub tcp_based_base: RequireTcpBasedAuth,
}
#[cfg(feature = "auth_tls")]
impl RequireTcpBasedAuthHandler<TlsStream<TcpStream>> for RequireTlsAuth {
    fn tcp_based_base(&self) -> &RequireTcpBasedAuth {
        &self.tcp_based_base
    }

    async fn bound_stream(&self, raw_stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        let config = Arc::new(self.properties.new_server_config()?);
        let acceptor = TlsAcceptor::from(config);
        Ok(acceptor.accept(raw_stream).await?)
    }

    fn inner_auth_of(&self, props: InnerAuthTcpBased) -> InnerAuth {
        InnerAuth::RequireTls(props)
    }
}
#[cfg(feature = "auth_tls")]
impl AuthModeHandler for RequireTlsAuth {
    require_tcp_based_auth_handler_impl_for_auth_mode!();
}
#[cfg(feature = "auth_tls")]
pub(super) struct RequireTlsAuthBuild {
    tls_read_signal_receiver: async_channel::Receiver<()>,
}

pub(super) enum AuthenticatorModeBuild {
    NoCryptography(Arc<NoCryptographyAuth>, NoCryptographyAuthBuild),
    #[cfg(feature = "auth_tcp")]
    RequireTcp(Arc<RequireTcpAuth>, RequireTcpAuthBuild),
    #[cfg(feature = "auth_tls")]
    RequireTls(Arc<RequireTlsAuth>, RequireTlsAuthBuild),
}

impl AuthenticatorModeBuild {
    pub(super) fn take_authenticator_mode_internal(&mut self) -> AuthenticatorModeInternal {
        match self {
            AuthenticatorModeBuild::NoCryptography(auth_mode, _) => {
                AuthenticatorModeInternal::NoCryptography(Arc::clone(&auth_mode))
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeBuild::RequireTcp(auth_mode, _) => {
                AuthenticatorModeInternal::RequireTcp(Arc::clone(&auth_mode))
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeBuild::RequireTls(auth_mode, _) => {
                AuthenticatorModeInternal::RequireTls(Arc::clone(&auth_mode))
            }
        }
    }

    pub(super) async fn apply(self, server: &Arc<ServerInternal>) -> io::Result<()> {
        match self {
            AuthenticatorModeBuild::NoCryptography(auth_mode, auth_mode_build) => {
                let server_downgraded = Arc::downgrade(&server);
                let auth_mode_downgraded = Arc::downgrade(&auth_mode);
                server.create_async_task(async move {
                    NoCryptographyAuth::create_pending_auth_resend_handler(
                        server_downgraded,
                        auth_mode_downgraded,
                        auth_mode_build.pending_auth_resend_receiver,
                    )
                    .await;
                });
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeBuild::RequireTcp(auth_mode, auth_mode_build) => {
                let server_downgraded = Arc::downgrade(&server);
                let auth_mode_downgraded = Arc::downgrade(&auth_mode);
                let listener = TcpListener::bind(auth_mode.properties.server_addr).await?;
                server.create_async_task(async move {
                    RequireTcpAuth::create_handler(
                        auth_mode_downgraded,
                        server_downgraded,
                        listener,
                        auth_mode_build.tcp_read_signal_receiver,
                    )
                    .await;
                });
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeBuild::RequireTls(auth_mode, auth_mode_build) => {
                let server_downgraded = Arc::downgrade(&server);
                let auth_mode_downgraded = Arc::downgrade(&auth_mode);
                let listener = TcpListener::bind(auth_mode.properties.server_addr).await?;
                server.create_async_task(async move {
                    RequireTlsAuth::create_handler(
                        auth_mode_downgraded,
                        server_downgraded,
                        listener,
                        auth_mode_build.tls_read_signal_receiver,
                    )
                    .await;
                });
            }
        }

        Ok(())
    }
}

pub(super) enum AuthenticatorModeInternal {
    NoCryptography(Arc<NoCryptographyAuth>),
    #[cfg(feature = "auth_tcp")]
    RequireTcp(Arc<RequireTcpAuth>),
    #[cfg(feature = "auth_tls")]
    RequireTls(Arc<RequireTlsAuth>),
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
    NoCryptography,
    /// Requires TCP-based key exchange for authentication.
    /// # Warning
    /// This authenticator alone is not responsible for encrypting the entire connection,
    /// the key exchange will be exposed if this TCP layer does not have a layer on top
    /// ensuring encryption, such as a reverse proxy.
    #[cfg(feature = "auth_tcp")]
    RequireTcp(AuthTcpServerProperties),
    /// Requires TLS-based key exchange for authentication.
    /// # Warning
    /// This authenticator uses `rustls` to cryptograph the key exchange between server and client.
    /// Ensure that the certificates provided in AuthTlsServerProperties are valid.
    #[cfg(feature = "auth_tls")]
    RequireTls(AuthTlsServerProperties),
}
impl AuthenticatorMode {
    pub(super) fn build(self) -> AuthenticatorModeBuild {
        match self {
            AuthenticatorMode::NoCryptography => {
                let (pending_auth_resend_sender, pending_auth_resend_receiver) =
                    async_channel::unbounded();

                AuthenticatorModeBuild::NoCryptography(
                    Arc::new(NoCryptographyAuth {
                        pending_auth_resend_sender,
                        pending_auth: DashMap::new(),
                        base: AuthMode {
                            addrs_in_auth: DashSet::new(),
                        },
                    }),
                    NoCryptographyAuthBuild {
                        pending_auth_resend_receiver,
                    },
                )
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorMode::RequireTcp(properties) => {
                let (read_signal_sender, read_signal_receiver) = async_channel::bounded(2);
                AuthenticatorModeBuild::RequireTcp(
                    Arc::new(RequireTcpAuth {
                        properties,
                        tcp_based_base: RequireTcpBasedAuth {
                            read_signal_sender,
                            pending_auth: DashMap::new(),
                            base: AuthMode {
                                addrs_in_auth: DashSet::new(),
                            },
                        },
                    }),
                    RequireTcpAuthBuild {
                        tcp_read_signal_receiver: read_signal_receiver,
                    },
                )
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorMode::RequireTls(properties) => {
                let (read_signal_sender, read_signal_receiver) = async_channel::bounded(2);
                AuthenticatorModeBuild::RequireTls(
                    Arc::new(RequireTlsAuth {
                        properties,
                        tcp_based_base: RequireTcpBasedAuth {
                            read_signal_sender,
                            pending_auth: DashMap::new(),
                            base: AuthMode {
                                addrs_in_auth: DashSet::new(),
                            },
                        },
                    }),
                    RequireTlsAuthBuild {
                        tls_read_signal_receiver: read_signal_receiver,
                    },
                )
            }
        }
    }
}
