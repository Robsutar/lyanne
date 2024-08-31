use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use dashmap::{DashMap, DashSet};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::{messages::DeserializedMessage, packets::SerializedPacketList, rt::timeout};

use crate::{MessageChannel, MESSAGE_CHANNEL_SIZE};

use super::*;

#[cfg(feature = "auth_tcp")]
use crate::auth_tcp::AuthTcpServerProperties;

#[cfg(feature = "auth_tls")]
use crate::auth_tls::{AuthTlsServerProperties, TlsAcceptor, TlsStream};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::rt::{AsyncReadExt, AsyncWriteExt, TcpListener, TcpStream};

/// Pending auth properties of a addr that is trying to connect.
///
/// Intended to use used inside [`Server#pending_auth`].
pub(super) struct AddrPendingAuthSend {
    /// The instant that the request was received.
    pub received_time: Instant,
    // pub TODO: that field is not used in RequireTls
    /// The last instant that the bytes were sent.
    pub last_sent_time: Option<Instant>,
    /// Random private key created inside the server.
    pub server_private_key: EphemeralSecret,
    /// Random public key created inside the server. Sent to the addr.
    pub server_public_key: PublicKey,
    /// Random public key created by the addr. Sent by the addr.
    pub addr_public_key: PublicKey,
    /// Finished bytes, with the channel and the server public key.
    pub finished_bytes: Vec<u8>,
}

/// Addr to auth properties, after a [`AddrPendingAuthSend`] is confirmed,
/// the next step is read the message of the addr, and authenticate it or no.
pub struct AddrToAuth {
    pub(super) shared_key: SharedSecret,
}

/// The reason to ignore messages from an addr.
pub struct IgnoredAddrReason {
    /// The message to send to the addr if it tries to authenticate.
    finished_bytes: Option<Vec<u8>>,
}

impl IgnoredAddrReason {
    /// No information will be returned to the client when it tries to connect.
    pub fn without_reason() -> Self {
        Self {
            finished_bytes: None,
        }
    }
    /// The message will be sent to the client when it tries to connect.
    pub fn from_serialized_list(list: SerializedPacketList) -> Self {
        if list.bytes.len() > 1024 - MESSAGE_CHANNEL_SIZE {
            panic!("Max bytes length reached.");
        }
        let mut finished_bytes = Vec::with_capacity(1 + list.bytes.len());
        finished_bytes.push(MessageChannel::IGNORED_REASON);
        finished_bytes.extend(list.bytes);
        Self {
            finished_bytes: Some(finished_bytes),
        }
    }
}

pub(super) struct AuthMode {
    /// Set of addrs in the authentication process.
    pub addrs_in_auth: DashSet<SocketAddr>,
    /// Map of pending authentication addresses.
    pub pending_auth: DashMap<PublicKey, AddrPendingAuthSend>,
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
    /// Sender for signaling the reading of [`Server::ignored_addrs_asking_reason`]
    pub ignored_addrs_asking_reason_read_signal_sender: async_channel::Sender<()>,

    /// Sender for resending authentication bytes, like the server public key.
    pub pending_auth_resend_sender: async_channel::Sender<SocketAddr>,

    /// Map of addresses asking for the reason they are ignored.
    pub ignored_addrs_asking_reason: DashMap<IpAddr, SocketAddr>,

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
                if let Some(mut context) = auth_mode.base().pending_auth.get_mut(&addr) {
                    context.last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            } else {
                break 'l1;
            }
        }
    }

    async fn create_ignored_addrs_asking_reason_handler(
        server: Weak<ServerInternal>,
        auth_mode: Weak<NoCryptographyAuth>,
        ignored_addrs_asking_reason_read_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = ignored_addrs_asking_reason_read_signal_receiver
            .recv()
            .await
        {
            if let (Some(server), Some(auth_mode)) = (server.upgrade(), auth_mode.upgrade()) {
                for addr in auth_mode.ignored_addrs_asking_reason.iter() {
                    let ip = addr.key();
                    if let Some(reason) = server.ignored_ips.get(&ip) {
                        if let Some(finished_bytes) = &reason.finished_bytes {
                            let _ = server.socket.send_to(&finished_bytes, addr.clone()).await;
                        }
                    }
                }
                auth_mode.ignored_addrs_asking_reason.clear();
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
        let ip = match addr {
            SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        };

        if let Some(reason) = internal.ignored_ips.get(&ip) {
            if reason.finished_bytes.is_some()
                && auth_mode.ignored_addrs_asking_reason.len()
                    < internal.server_properties.max_ignored_addrs_asking_reason
            {
                auth_mode.ignored_addrs_asking_reason.insert(ip, addr);
            }
            ReadClientBytesResult::IgnoredClientHandle
        } else if let Some(client) = internal.connected_clients.get(&addr) {
            let mut messaging = client.messaging.lock().await;
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 20;
            if messaging.tick_bytes_len > internal.messaging_properties.max_client_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.try_send(bytes);
                ReadClientBytesResult::ClientReceivedBytes
            }
        } else if auth_mode.base().addrs_in_auth.contains(&addr) {
            ReadClientBytesResult::AddrInAuth
        } else if let Some((_, pending_auth_send)) = auth_mode.base().pending_auth.remove(&addr) {
            if bytes[0] == MessageChannel::AUTH_MESSAGE {
                // 32 for public key, and 1 for the smallest possible serialized packet
                if bytes.len() < MESSAGE_CHANNEL_SIZE + 32 + 1 {
                    ReadClientBytesResult::AuthInsufficientBytesLen
                } else {
                    let message = DeserializedMessage::deserialize_single_list(
                        &bytes[33..],
                        &internal.packet_registry,
                    );
                    if let Ok(message) = message {
                        let mut sent_server_public_key: [u8; 32] = [0; 32];
                        sent_server_public_key.copy_from_slice(&bytes[1..33]);
                        let sent_server_public_key = PublicKey::from(sent_server_public_key);

                        if sent_server_public_key != pending_auth_send.server_public_key {
                            ReadClientBytesResult::InvalidPendingAuth
                        } else {
                            auth_mode.base().addrs_in_auth.insert(addr.clone());
                            let _ = internal.clients_to_auth_sender.try_send((
                                addr,
                                (
                                    AddrToAuth {
                                        shared_key: pending_auth_send
                                            .server_private_key
                                            .diffie_hellman(&pending_auth_send.addr_public_key),
                                    },
                                    message,
                                ),
                            ));
                            ReadClientBytesResult::DonePendingAuth
                        }
                    } else {
                        internal.ignore_ip_temporary(
                            ip,
                            IgnoredAddrReason::without_reason(),
                            Instant::now() + Duration::from_secs(5),
                        );
                        ReadClientBytesResult::InvalidPendingAuth
                    }
                }
            } else {
                auth_mode
                    .base()
                    .pending_auth
                    .insert(addr, pending_auth_send);
                ReadClientBytesResult::PendingPendingAuth
            }
        } else if bytes[0] == MessageChannel::PUBLIC_KEY_SEND && bytes.len() == 33 {
            let mut client_public_key: [u8; 32] = [0; 32];
            client_public_key.copy_from_slice(&bytes[1..33]);
            let client_public_key = PublicKey::from(client_public_key);
            let server_private_key = EphemeralSecret::random_from_rng(OsRng);
            let server_public_key = PublicKey::from(&server_private_key);
            let server_public_key_bytes = server_public_key.as_bytes();

            let mut finished_bytes = Vec::with_capacity(1 + server_public_key_bytes.len());
            finished_bytes.push(MessageChannel::PUBLIC_KEY_SEND);
            finished_bytes.extend_from_slice(server_public_key_bytes);

            auth_mode.base().pending_auth.insert(
                addr,
                AddrPendingAuthSend {
                    received_time: Instant::now(),
                    last_sent_time: None,
                    server_private_key,
                    server_public_key,
                    addr_public_key: client_public_key,
                    finished_bytes,
                },
            );
            ReadClientBytesResult::PublicKeySend
        } else {
            ReadClientBytesResult::InvalidPublicKeySend
        }
    }
}
impl AuthModeHandler for NoCryptographyAuth {
    fn base(&self) -> &AuthMode {
        &self.base
    }

    fn retain_pending_auth(&self, internal: &ServerInternal, now: Instant) {
        self.base().pending_auth.retain(|_, pending_auth_send| {
            now - pending_auth_send.received_time
                < internal.messaging_properties.timeout_interpretation
        });
        for context in self.base().pending_auth.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time
                    < internal
                        .server_properties
                        .pending_auth_packet_loss_interpretation
                {
                    continue;
                }
            }
            self.pending_auth_resend_sender
                .try_send(context.key().clone())
                .unwrap();
        }
    }

    fn call_tick_start_signal(&self) {
        self.ignored_addrs_asking_reason_read_signal_sender
            .try_send(())
            .unwrap();
    }
}
pub(super) struct NoCryptographyAuthBuild {
    pending_auth_resend_receiver: async_channel::Receiver<SocketAddr>,
    ignored_addrs_asking_reason_read_signal_receiver: async_channel::Receiver<()>,
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub(super) struct RequireTcpBasedAuth {
    pub base: AuthMode,

    pub read_signal_sender: async_channel::Sender<()>,
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
            if let (Some(server), Some(auth_mode)) = (server.upgrade(), auth_mode.upgrade()) {
                let accepted =
                    timeout(server.read_handler_properties.timeout, listener.accept()).await;

                if let Ok(accepted) = accepted {
                    if let Ok((stream, addr)) = accepted {
                        // TODO: use this
                        let _result = auth_mode.handler_accept(&server, addr, stream).await;
                    }
                }
            } else {
                break 'l1;
            }
        }
    }

    async fn bound_stream(&self, raw_stream: TcpStream) -> io::Result<T>;

    async fn handler_accept(
        &self,
        server: &ServerInternal,
        addr: SocketAddr,
        raw_stream: TcpStream,
    ) -> io::Result<ReadClientBytesResult> {
        let mut bound_stream = self.bound_stream(raw_stream).await?;

        let ip = match addr {
            SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        };

        if let Some(reason) = server.ignored_ips.get(&ip) {
            if
            /*TODO:auth_mode.ignored_addrs_asking_reason.len()*/
            0usize < server.server_properties.max_ignored_addrs_asking_reason {
                if let Some(finished_bytes) = &reason.finished_bytes {
                    bound_stream.write_all(finished_bytes).await?
                }
            }
            Ok(ReadClientBytesResult::IgnoredClientHandle)
        } else if server.connected_clients.contains_key(&addr) {
            Ok(ReadClientBytesResult::AlreadyConnected)
        } else if self.tcp_based_base().base.addrs_in_auth.contains(&addr) {
            Ok(ReadClientBytesResult::AddrInAuth)
        } else {
            let mut buf = [0u8; 1024];

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

            if bytes[0] == MessageChannel::PUBLIC_KEY_SEND && bytes.len() == 33 {
                let mut client_public_key: [u8; 32] = [0; 32];
                client_public_key.copy_from_slice(&bytes[1..33]);
                let client_public_key = PublicKey::from(client_public_key);

                let mut server_private_key = EphemeralSecret::random_from_rng(OsRng);
                let mut server_public_key = PublicKey::from(&server_private_key);
                while self
                    .tcp_based_base()
                    .base
                    .pending_auth
                    .contains_key(&server_public_key)
                {
                    server_private_key = EphemeralSecret::random_from_rng(OsRng);
                    server_public_key = PublicKey::from(&server_private_key);
                }
                let server_public_key_bytes = server_public_key.as_bytes();

                let mut finished_bytes = Vec::with_capacity(1 + server_public_key_bytes.len());
                finished_bytes.push(MessageChannel::PUBLIC_KEY_SEND);
                finished_bytes.extend_from_slice(server_public_key_bytes);

                self.tcp_based_base().base.pending_auth.insert(
                    server_public_key.clone(),
                    AddrPendingAuthSend {
                        received_time: Instant::now(),
                        last_sent_time: None,
                        server_private_key,
                        server_public_key: server_public_key.clone(),
                        addr_public_key: client_public_key,
                        finished_bytes,
                    },
                );

                let addr_pending_auth = self
                    .tcp_based_base()
                    .base
                    .pending_auth
                    .get(&server_public_key)
                    .unwrap();
                bound_stream
                    .write_all(&addr_pending_auth.finished_bytes)
                    .await?;

                Ok(ReadClientBytesResult::PublicKeySend)
            } else {
                Ok(ReadClientBytesResult::InvalidPublicKeySend)
            }
        }
    }

    async fn read_next_bytes(
        &self,
        internal: &ServerInternal,
        addr: SocketAddr,
        bytes: Vec<u8>,
    ) -> ReadClientBytesResult {
        let ip = match addr {
            SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        };

        if let Some(client) = internal.connected_clients.get(&addr) {
            let mut messaging = client.messaging.lock().await;
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 20;
            if messaging.tick_bytes_len > internal.messaging_properties.max_client_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.try_send(bytes);
                ReadClientBytesResult::ClientReceivedBytes
            }
        } else if self.tcp_based_base().base.addrs_in_auth.contains(&addr) {
            ReadClientBytesResult::AddrInAuth
        } else if bytes[0] == MessageChannel::AUTH_MESSAGE {
            // 32 for public key, and 1 for the smallest possible serialized packet
            if bytes.len() < MESSAGE_CHANNEL_SIZE + 32 + 1 {
                return ReadClientBytesResult::AuthInsufficientBytesLen;
            }

            let mut sent_server_public_key: [u8; 32] = [0; 32];
            sent_server_public_key.copy_from_slice(&bytes[1..33]);
            let sent_server_public_key = PublicKey::from(sent_server_public_key);

            if let Some((_, pending_auth_send)) = self
                .tcp_based_base()
                .base
                .pending_auth
                .remove(&sent_server_public_key)
            {
                // 32 for public key, and 1 for the smallest possible serialized packet
                if bytes.len() < MESSAGE_CHANNEL_SIZE + 32 + 1 {
                    ReadClientBytesResult::AuthInsufficientBytesLen
                } else {
                    let message = DeserializedMessage::deserialize_single_list(
                        &bytes[33..],
                        &internal.packet_registry,
                    );
                    if let Ok(message) = message {
                        let mut sent_server_public_key: [u8; 32] = [0; 32];
                        sent_server_public_key.copy_from_slice(&bytes[1..33]);
                        let sent_server_public_key = PublicKey::from(sent_server_public_key);

                        if sent_server_public_key != pending_auth_send.server_public_key {
                            ReadClientBytesResult::InvalidPendingAuth
                        } else {
                            self.tcp_based_base()
                                .base
                                .addrs_in_auth
                                .insert(addr.clone());
                            let _ = internal.clients_to_auth_sender.try_send((
                                addr,
                                (
                                    AddrToAuth {
                                        shared_key: pending_auth_send
                                            .server_private_key
                                            .diffie_hellman(&pending_auth_send.addr_public_key),
                                    },
                                    message,
                                ),
                            ));
                            ReadClientBytesResult::DonePendingAuth
                        }
                    } else {
                        internal.ignore_ip_temporary(
                            ip,
                            IgnoredAddrReason::without_reason(),
                            Instant::now() + Duration::from_secs(5),
                        );
                        ReadClientBytesResult::InvalidPendingAuth
                    }
                }
            } else {
                todo!("")
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
            self.base().pending_auth.retain(|_, pending_auth_send| {
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

                let server_downgraded = Arc::downgrade(&server);
                let auth_mode_downgraded = Arc::downgrade(&auth_mode);
                server.create_async_task(async move {
                    NoCryptographyAuth::create_ignored_addrs_asking_reason_handler(
                        server_downgraded,
                        auth_mode_downgraded,
                        auth_mode_build.ignored_addrs_asking_reason_read_signal_receiver,
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

pub enum AuthenticatorMode {
    NoCryptography,
    #[cfg(feature = "auth_tcp")]
    RequireTcp(AuthTcpServerProperties),
    #[cfg(feature = "auth_tls")]
    RequireTls(AuthTlsServerProperties),
}
impl AuthenticatorMode {
    pub(super) fn build(self) -> AuthenticatorModeBuild {
        match self {
            AuthenticatorMode::NoCryptography => {
                let (pending_auth_resend_sender, pending_auth_resend_receiver) =
                    async_channel::unbounded();
                let (
                    ignored_addrs_asking_reason_read_signal_sender,
                    ignored_addrs_asking_reason_read_signal_receiver,
                ) = async_channel::unbounded();

                AuthenticatorModeBuild::NoCryptography(
                    Arc::new(NoCryptographyAuth {
                        ignored_addrs_asking_reason_read_signal_sender,
                        pending_auth_resend_sender,
                        ignored_addrs_asking_reason: DashMap::new(),

                        base: AuthMode {
                            addrs_in_auth: DashSet::new(),
                            pending_auth: DashMap::new(),
                        },
                    }),
                    NoCryptographyAuthBuild {
                        pending_auth_resend_receiver,
                        ignored_addrs_asking_reason_read_signal_receiver,
                    },
                )
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorMode::RequireTcp(properties) => {
                // TODO: configure that 5
                let (read_signal_sender, read_signal_receiver) = async_channel::bounded(5);
                AuthenticatorModeBuild::RequireTcp(
                    Arc::new(RequireTcpAuth {
                        properties,
                        tcp_based_base: RequireTcpBasedAuth {
                            read_signal_sender,
                            base: AuthMode {
                                addrs_in_auth: DashSet::new(),
                                pending_auth: DashMap::new(),
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
                // TODO: configure that 5
                let (read_signal_sender, read_signal_receiver) = async_channel::bounded(5);
                AuthenticatorModeBuild::RequireTls(
                    Arc::new(RequireTlsAuth {
                        properties,
                        tcp_based_base: RequireTcpBasedAuth {
                            read_signal_sender,
                            base: AuthMode {
                                addrs_in_auth: DashSet::new(),
                                pending_auth: DashMap::new(),
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
