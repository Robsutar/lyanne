use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, ChaChaPoly1305, Key};
use dashmap::{DashMap, DashSet};

use crate::{
    messages::{DeserializedMessage, MessageId, MessagePartId, MessagePartMap},
    packets::{
        Packet, PacketRegistry, SerializedPacket, SerializedPacketList, ServerTickEndPacket,
    },
    rt::{spawn, timeout, try_lock, Mutex, TaskHandle, UdpSocket},
    utils::{DurationMonitor, RttCalculator},
};

use crate::{
    JustifiedRejectionContext, MessageChannel, MessagingProperties, ReadHandlerProperties,
    SentMessagePart, MESSAGE_CHANNEL_SIZE,
};

pub use auth::*;

mod auth;
mod init;

/// Possible results when receiving bytes by clients.
#[derive(Debug)]
pub enum ReadClientBytesResult {
    /// Disconnect confirmation from the client is done.
    DoneDisconnectConfirm,
    /// Client handle is ignored.
    IgnoredClientHandle,
    /// Bytes were successfully received from the client.
    ClientReceivedBytes,
    /// Pending authentication is completed.
    DonePendingAuth,
    /// The public key has been successfully sent.
    PublicKeySend,
    /// Some client that was disconnected itself recently is resending the disconnect justification.
    RecentClientDisconnectConfirm,

    /// The received byte length is insufficient.
    InsufficientBytesLen,
    /// Disconnect confirmation from the client is pending.
    PendingDisconnectConfirm,
    /// Address is in the authentication process.
    AddrInAuth,
    /// The byte length for authentication is insufficient.
    AuthInsufficientBytesLen,
    /// The client has exceeded the maximum tick byte length.
    ClientMaxTickByteLenOverflow,
    /// The pending authentication is invalid.
    InvalidPendingAuth,
    /// The pending authentication is still in process.
    PendingPendingAuth,
    /// The public key send operation is invalid.
    InvalidPublicKeySend,
    /// The client tried to authenticate, but it is already connected.
    AlreadyConnected,
}

impl ReadClientBytesResult {
    pub fn is_unexpected(&self) -> bool {
        match self {
            ReadClientBytesResult::DoneDisconnectConfirm => false,
            ReadClientBytesResult::IgnoredClientHandle => false,
            ReadClientBytesResult::ClientReceivedBytes => false,
            ReadClientBytesResult::DonePendingAuth => false,
            ReadClientBytesResult::PublicKeySend => false,
            ReadClientBytesResult::RecentClientDisconnectConfirm => false,
            ReadClientBytesResult::InsufficientBytesLen => true,
            ReadClientBytesResult::PendingDisconnectConfirm => true,
            ReadClientBytesResult::AddrInAuth => true,
            ReadClientBytesResult::AuthInsufficientBytesLen => true,
            ReadClientBytesResult::ClientMaxTickByteLenOverflow => true,
            ReadClientBytesResult::InvalidPendingAuth => true,
            ReadClientBytesResult::PendingPendingAuth => true,
            ReadClientBytesResult::InvalidPublicKeySend => true,
            ReadClientBytesResult::AlreadyConnected => true,
        }
    }
}

/// Possible reasons to be disconnected from some client.
///
/// Used after the client was already disconnected.
#[derive(Debug)]
pub enum ClientDisconnectReason {
    /// Client was disconnected due to a timeout waiting for message confirmation.
    PendingMessageConfirmationTimeout,
    /// Client was disconnected because it did not receive messages within the expected time frame.
    MessageReceiveTimeout,
    /// Client was disconnected due to a timeout while trying to acquire a write lock.
    WriteUnlockTimeout,
    /// Client was disconnected due to invalid protocol communication.
    InvalidProtocolCommunication,
    /// Client was disconnected because of an error while sending bytes.
    ByteSendError(io::Error),
    /// Client was manually disconnected.
    ManualDisconnect,
    /// Client disconnected itself.
    DisconnectRequest(DeserializedMessage),
}

/// General properties for the server management.
///
/// # Warning
/// The default version does not use cryptography.
pub struct ServerProperties {
    pub max_ignored_addrs_asking_reason: usize,
    pub pending_auth_packet_loss_interpretation: Duration,
}

impl Default for ServerProperties {
    fn default() -> Self {
        Self {
            max_ignored_addrs_asking_reason: 50,
            pending_auth_packet_loss_interpretation: Duration::from_secs(3),
        }
    }
}

/// Result when calling [`Server::bind`].
pub struct BindResult {
    pub server: Server,
}

/// Server tick flow state.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerTickState {
    /// Next call should be [`Server::tick_start`].
    TickStartPending,
    /// Next call should be [`Server::tick_end`].
    TickEndPending,
}

#[cfg(feature = "store_unexpected")]
#[derive(Debug)]
pub enum UnexpectedError {
    OfReadAddrBytes(SocketAddr, ReadClientBytesResult),
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    OfTcpBasedHandlerAccept(SocketAddr, ReadClientBytesResult),
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    OfTcpBasedHandlerAcceptIoError(SocketAddr, io::Error),
}

#[cfg(feature = "store_unexpected")]
struct StoreUnexpectedErrors {
    error_sender: async_channel::Sender<UnexpectedError>,
    error_receiver: async_channel::Receiver<UnexpectedError>,
    error_list_sender: async_channel::Sender<Vec<UnexpectedError>>,
    error_list_receiver: async_channel::Receiver<Vec<UnexpectedError>>,

    create_list_signal_sender: async_channel::Sender<()>,
}

/// Result when calling [`Server::tick_start`].
pub struct ServerTickResult {
    pub received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>>,
    pub to_auth: HashMap<SocketAddr, (AddrToAuth, DeserializedMessage)>,
    pub disconnected: HashMap<SocketAddr, ClientDisconnectReason>,
    #[cfg(feature = "store_unexpected")]
    pub unexpected_errors: Vec<UnexpectedError>,
}

/// Messaging fields of [`ConnectedClient`].
///
/// Intended to be used with [`Mutex`].
struct ConnectedClientMessaging {
    /// The cipher used for encrypting and decrypting messages.
    cipher: ChaCha20Poly1305,

    /// Map of message parts pending confirmation.
    /// The tuple is the sent instant, and the map of the message parts of the message.
    pending_confirmation: BTreeMap<MessageId, (Instant, BTreeMap<MessagePartId, SentMessagePart>)>,

    /// Map of incoming messages parts.
    incoming_messages: MessagePartMap,
    /// The length of bytes received in the current tick.
    tick_bytes_len: usize,

    /// The instant when the last message was received.
    last_received_message_instant: Instant,
    /// The deserialized messages that have been received and have not been read yet.
    received_messages: Vec<DeserializedMessage>,

    /// Calculator for packet loss round-trip time.
    packet_loss_rtt_calculator: RttCalculator,
    /// The average round-trip time for packet loss.
    average_packet_loss_rtt: Duration,
    /// Monitor for latency duration.
    latency_monitor: DurationMonitor,
}

/// Properties of a client that is connected to the server.
///
/// Intended to be used inside [`ServerInternal`] with [`Arc`].
pub struct ConnectedClient {
    /// Sender for receiving bytes.
    receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    /// Sender for packets to be sent.
    packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,
    /// Sender for message part confirmations.
    message_part_confirmation_sender: async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

    /// The socket address of the connected client.
    addr: SocketAddr,

    /// Messaging-related properties wrapped in an [`Mutex`].
    messaging: Mutex<ConnectedClientMessaging>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,
    /// The byte size of [`ConnectedClientMessaging::incoming_messages`]
    incoming_messages_total_size: RwLock<usize>,
}

impl ConnectedClient {
    /// # Returns
    /// The average time of messaging response of this client after a server message.
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    /// # Returns
    /// The total size of the stored incoming messages, that were not completed wet, or not read yet.
    pub fn incoming_messages_total_size(&self) -> usize {
        *self.incoming_messages_total_size.read().unwrap()
    }
}

/// Properties of the server.
///
/// Intended to be used inside [`Server`].
struct ServerInternal {
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: async_channel::Sender<TaskHandle<()>>,
    /// Sender for addresses to be authenticated.
    clients_to_auth_sender: async_channel::Sender<(SocketAddr, (AddrToAuth, DeserializedMessage))>,
    /// Sender for addresses to be disconnected.
    clients_to_disconnect_sender: async_channel::Sender<(
        SocketAddr,
        (ClientDisconnectReason, Option<JustifiedRejectionContext>),
    )>,

    /// Sender for signaling the reading of [`Server::rejections_to_confirm`]
    rejections_to_confirm_signal_sender: async_channel::Sender<()>,
    /// Sender for resending pending rejection confirmations.
    pending_rejection_confirm_resend_sender: async_channel::Sender<SocketAddr>,

    /// Receiver for addresses to be authenticated.
    clients_to_auth_receiver:
        async_channel::Receiver<(SocketAddr, (AddrToAuth, DeserializedMessage))>,

    /// Receiver for addresses to be disconnected.
    clients_to_disconnect_receiver: async_channel::Receiver<(
        SocketAddr,
        (ClientDisconnectReason, Option<JustifiedRejectionContext>),
    )>,

    #[cfg(feature = "store_unexpected")]
    /// List of errors emitted in the tick.
    store_unexpected_errors: StoreUnexpectedErrors,

    authenticator_mode: AuthenticatorModeInternal,

    /// Task handle of the receiver.
    tasks_keeper_handle: TaskHandle<()>,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    #[cfg(feature = "rt_tokio")]
    /// The runtime for asynchronous operations.
    runtime: crate::rt::Runtime,
    /// Actual state of server periodic tick flow.
    tick_state: RwLock<ServerTickState>,

    /// The registry for packets.
    packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    read_handler_properties: Arc<ReadHandlerProperties>,
    /// Properties for the internal server management.
    server_properties: Arc<ServerProperties>,

    /// Map of connected clients, keyed by their socket address.
    connected_clients: DashMap<SocketAddr, Arc<ConnectedClient>>,

    /// Map of ignored addresses with reasons for ignoring them.
    ignored_ips: DashMap<IpAddr, IgnoredAddrReason>,
    /// Map of temporarily ignored addresses with the time until they are ignored.
    temporary_ignored_ips: DashMap<IpAddr, Instant>,

    /// Lock-protected set of assigned addresses in authentication.
    assigned_addrs_in_auth: RwLock<HashSet<SocketAddr>>,

    /// Map of clients that were recently disconnected itself.
    recently_disconnected: DashMap<SocketAddr, Instant>,
    /// Map of pending rejection confirmations.
    pending_rejection_confirm: DashMap<SocketAddr, JustifiedRejectionContext>,
    /// Set of addresses asking for the rejection confirm.
    rejections_to_confirm: DashSet<SocketAddr>,
}

impl ServerInternal {
    fn ignore_ip(&self, ip: IpAddr, reason: IgnoredAddrReason) {
        self.temporary_ignored_ips.remove(&ip);
        self.ignored_ips.insert(ip, reason);
    }

    fn ignore_ip_temporary(&self, ip: IpAddr, reason: IgnoredAddrReason, until_to: Instant) {
        self.ignored_ips.insert(ip, reason);
        self.temporary_ignored_ips.insert(ip, until_to);
    }

    fn remove_ignore_ip(&self, ip: &IpAddr) {
        self.ignored_ips.remove(ip);
        self.temporary_ignored_ips.remove(ip);
    }

    fn create_async_task<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        #[cfg(feature = "rt_tokio")]
        {
            let _ = self
                .tasks_keeper_sender
                .try_send(spawn(&self.runtime, future));
        }
        #[cfg(feature = "rt_bevy")]
        {
            let _ = self.tasks_keeper_sender.try_send(spawn(future));
        }
    }

    fn try_check_read_handler(self: &Arc<Self>) {
        if let Ok(mut active_count) = self.read_handler_properties.active_count.try_write() {
            if *active_count < self.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&self);
                self.create_async_task(async move {
                    init::server::create_read_handler(downgraded_server).await;
                });
            }
        }
    }

    async fn pre_read_next_bytes(
        socket: &Arc<UdpSocket>,
        read_timeout: Duration,
    ) -> io::Result<(SocketAddr, Vec<u8>)> {
        let pre_read_next_bytes_result: Result<io::Result<(SocketAddr, Vec<u8>)>, ()> =
            timeout(read_timeout, async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = socket.recv_from(&mut buf).await?;
                Ok((addr, buf[..len].to_vec()))
            })
            .await;

        match pre_read_next_bytes_result {
            Ok(result) => match result {
                Ok(result) => Ok(result),
                Err(e) => Err(e),
            },
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Timeout of {:?}", read_timeout),
            )),
        }
    }

    async fn read_next_bytes(
        self: &Arc<Self>,
        tuple: (SocketAddr, Vec<u8>),
    ) -> ReadClientBytesResult {
        let (addr, bytes) = tuple;

        if bytes.len() < MESSAGE_CHANNEL_SIZE {
            return ReadClientBytesResult::InsufficientBytesLen;
        }

        if self.pending_rejection_confirm.contains_key(&addr) {
            if bytes[0] == MessageChannel::REJECTION_CONFIRM {
                self.pending_rejection_confirm.remove(&addr);
                return ReadClientBytesResult::DoneDisconnectConfirm;
            } else {
                return ReadClientBytesResult::PendingDisconnectConfirm;
            }
        }

        if bytes[0] == MessageChannel::REJECTION_JUSTIFICATION {
            if self.recently_disconnected.contains_key(&addr) {
                self.rejections_to_confirm.insert(addr);
                return ReadClientBytesResult::RecentClientDisconnectConfirm;
            } else {
                return ReadClientBytesResult::InvalidPublicKeySend;
            }
        }

        match &self.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                NoCryptographyAuth::read_next_bytes(&self, addr, bytes, auth_mode).await
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.read_next_bytes(&self, addr, bytes).await
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.read_next_bytes(&self, addr, bytes).await
            }
        }
    }
}

/// Connected server.
pub struct Server {
    internal: Arc<ServerInternal>,
}

impl Server {
    /// Bind a [`UdpSocket´], to create a new Server instance
    pub fn bind(
        addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        server_properties: Arc<ServerProperties>,
        authenticator_mode: AuthenticatorMode,
        #[cfg(feature = "rt_tokio")] runtime: crate::rt::Runtime,
    ) -> TaskHandle<io::Result<BindResult>> {
        #[cfg(feature = "rt_tokio")]
        let runtime_exit = runtime.clone();

        let bind_result_body = async move {
            let socket = Arc::new(UdpSocket::bind(addr).await?);

            let (tasks_keeper_sender, tasks_keeper_receiver) = async_channel::unbounded();

            let (clients_to_auth_sender, clients_to_auth_receiver) = async_channel::unbounded();
            let (clients_to_disconnect_sender, clients_to_disconnect_receiver) =
                async_channel::unbounded();

            let (
                pending_rejection_confirm_resend_sender,
                pending_rejection_confirm_resend_receiver,
            ) = async_channel::unbounded();
            let (rejections_to_confirm_signal_sender, rejections_to_confirm_signal_receiver) =
                async_channel::unbounded();

            let tasks_keeper_handle;
            #[cfg(feature = "rt_tokio")]
            {
                tasks_keeper_handle = spawn(
                    &runtime,
                    init::server::create_async_tasks_keeper(tasks_keeper_receiver),
                );
            }

            #[cfg(feature = "rt_bevy")]
            {
                tasks_keeper_handle = spawn(init::server::create_async_tasks_keeper(
                    tasks_keeper_receiver,
                ));
            }

            #[cfg(feature = "store_unexpected")]
            let (store_unexpected_errors, store_unexpected_errors_create_list_signal_receiver) = {
                let (error_sender, error_receiver) = async_channel::unbounded();
                let (error_list_sender, error_list_receiver) = async_channel::unbounded();
                let (create_list_signal_sender, create_list_signal_receiver) =
                    async_channel::unbounded();

                (
                    StoreUnexpectedErrors {
                        error_sender,
                        error_receiver,
                        error_list_sender,
                        error_list_receiver,
                        create_list_signal_sender,
                    },
                    create_list_signal_receiver,
                )
            };

            let mut authenticator_mode_build = authenticator_mode.build();

            let server = Arc::new(ServerInternal {
                tasks_keeper_sender,
                clients_to_auth_sender,
                clients_to_disconnect_sender,

                rejections_to_confirm_signal_sender,
                pending_rejection_confirm_resend_sender,

                clients_to_auth_receiver,

                clients_to_disconnect_receiver,

                #[cfg(feature = "store_unexpected")]
                store_unexpected_errors,

                authenticator_mode: authenticator_mode_build.take_authenticator_mode_internal(),
                tasks_keeper_handle,
                socket,

                tick_state: RwLock::new(ServerTickState::TickStartPending),
                packet_registry,
                messaging_properties,
                read_handler_properties,

                server_properties,
                connected_clients: DashMap::new(),
                ignored_ips: DashMap::new(),
                temporary_ignored_ips: DashMap::new(),

                assigned_addrs_in_auth: RwLock::new(HashSet::new()),
                recently_disconnected: DashMap::new(),
                pending_rejection_confirm: DashMap::new(),
                rejections_to_confirm: DashSet::new(),
                #[cfg(feature = "rt_tokio")]
                runtime,
            });

            authenticator_mode_build.apply(&server).await?;

            let server_downgraded = Arc::downgrade(&server);
            server.create_async_task(async move {
                init::server::create_pending_rejection_confirm_resend_handler(
                    server_downgraded,
                    pending_rejection_confirm_resend_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&server);
            server.create_async_task(async move {
                init::server::create_rejections_to_confirm_handler(
                    server_downgraded,
                    rejections_to_confirm_signal_receiver,
                )
                .await;
            });

            #[cfg(feature = "store_unexpected")]
            {
                let server_downgraded = Arc::downgrade(&server);
                server.create_async_task(async move {
                    init::server::create_store_unexpected_error_list_handler(
                        server_downgraded,
                        store_unexpected_errors_create_list_signal_receiver,
                    )
                    .await;
                });
            }

            Ok(BindResult {
                server: Server { internal: server },
            })
        };

        spawn(
            #[cfg(feature = "rt_tokio")]
            &runtime_exit,
            bind_result_body,
        )
    }

    /// Packet Registry getter.
    pub fn packet_registry(&self) -> &PacketRegistry {
        &self.internal.packet_registry
    }

    /// Messaging Properties getter.
    pub fn messaging_properties(&self) -> &MessagingProperties {
        &self.internal.messaging_properties
    }

    /// Read Handler Properties getter.
    pub fn read_handler_properties(&self) -> &ReadHandlerProperties {
        &self.internal.read_handler_properties
    }

    /// Server Properties getter.
    pub fn server_properties(&self) -> &ServerProperties {
        &self.internal.server_properties
    }

    /// Server periodic tick start.
    ///
    /// The server tick ratio is based on this function call.
    ///
    /// It handles:
    /// - Pending authentications
    /// - Pending disconnections
    /// - Clients sent packets
    /// - General server cyclic management
    ///
    /// # Panics
    /// If [`Server::tick_end`] call is pending. That is, the cycle must be:
    /// - [`Server::tick_start`]
    /// - [`Server::tick_end`]
    /// - [`Server::tick_start`]
    /// - [`Server::tick_end`]
    /// - ...
    pub fn tick_start(&self) -> ServerTickResult {
        let internal = &self.internal;
        {
            let mut tick_state = internal.tick_state.write().unwrap();
            if *tick_state != ServerTickState::TickStartPending {
                panic!(
                    "Invalid server tick state, next pending is {:?}",
                    tick_state
                );
            } else {
                *tick_state = ServerTickState::TickEndPending;
            }
        }

        let now = Instant::now();

        let mut assigned_addrs_in_auth = internal.assigned_addrs_in_auth.write().unwrap();
        let dispatched_assigned_addrs_in_auth = std::mem::take(&mut *assigned_addrs_in_auth);

        match &internal.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
        }

        #[cfg(feature = "store_unexpected")]
        let unexpected_errors = match internal
            .store_unexpected_errors
            .error_list_receiver
            .try_recv()
        {
            Ok(list) => list,
            Err(_) => Vec::new(),
        };

        internal.recently_disconnected.retain(|_, received_time| {
            now - *received_time < internal.messaging_properties.timeout_interpretation
        });

        internal.temporary_ignored_ips.retain(|addr, until_to| {
            if now < *until_to {
                true
            } else {
                internal.ignored_ips.remove(addr);
                false
            }
        });

        let mut received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>> = HashMap::new();
        let mut to_auth: HashMap<SocketAddr, (AddrToAuth, DeserializedMessage)> = HashMap::new();
        let mut disconnected: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

        let mut addrs_to_disconnect: HashMap<
            SocketAddr,
            (ClientDisconnectReason, Option<JustifiedRejectionContext>),
        > = HashMap::new();

        while let Ok((addr, addr_to_auth)) = internal.clients_to_auth_receiver.try_recv() {
            to_auth.insert(addr, addr_to_auth);
        }

        while let Ok((addr, reason)) = internal.clients_to_disconnect_receiver.try_recv() {
            if !addrs_to_disconnect.contains_key(&addr) {
                addrs_to_disconnect.insert(addr, reason);
            }
        }

        'l1: for client in internal.connected_clients.iter() {
            if addrs_to_disconnect.contains_key(client.key()) {
                continue 'l1;
            }
            if let Some(mut messaging) = try_lock(&client.messaging) {
                *client.last_messaging_write.write().unwrap() = now;
                *client.average_latency.write().unwrap() =
                    messaging.latency_monitor.average_value();

                let average_packet_loss_rtt = messaging.average_packet_loss_rtt;
                let mut messages_to_resend: Vec<Arc<Vec<u8>>> = Vec::new();

                for (sent_instant, pending_part_id_map) in
                    messaging.pending_confirmation.values_mut()
                {
                    if now - *sent_instant > internal.messaging_properties.timeout_interpretation {
                        addrs_to_disconnect.insert(
                            client.key().clone(),
                            (
                                ClientDisconnectReason::PendingMessageConfirmationTimeout,
                                None,
                            ),
                        );
                        continue 'l1;
                    }
                    for sent_part in pending_part_id_map.values_mut() {
                        if now - sent_part.last_sent_time > average_packet_loss_rtt {
                            sent_part.last_sent_time = now;
                            messages_to_resend.push(Arc::clone(&sent_part.finished_bytes));
                        }
                    }
                }

                for finished_bytes in messages_to_resend {
                    client
                        .shared_socket_bytes_send_sender
                        .try_send(finished_bytes)
                        .unwrap();
                }

                if !messaging.received_messages.is_empty() {
                    let messages = std::mem::replace(&mut messaging.received_messages, Vec::new());
                    messaging.tick_bytes_len = 0;
                    received_messages.insert(client.key().clone(), messages);
                } else if now - messaging.last_received_message_instant
                    >= internal.messaging_properties.timeout_interpretation
                {
                    addrs_to_disconnect.insert(
                        client.key().clone(),
                        (ClientDisconnectReason::MessageReceiveTimeout, None),
                    );
                    continue 'l1;
                }
            } else if now - *client.last_messaging_write.read().unwrap()
                >= internal.messaging_properties.timeout_interpretation
            {
                addrs_to_disconnect.insert(
                    client.key().clone(),
                    (ClientDisconnectReason::WriteUnlockTimeout, None),
                );
                continue 'l1;
            }
        }

        internal.pending_rejection_confirm.retain(|_, context| {
            now - context.rejection_instant
                < internal
                    .messaging_properties
                    .disconnect_reason_resend_cancel
        });
        for context in internal.pending_rejection_confirm.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time
                    < internal.messaging_properties.disconnect_reason_resend_delay
                {
                    continue;
                }
            }
            internal
                .pending_rejection_confirm_resend_sender
                .try_send(context.key().clone())
                .unwrap();
        }

        for (addr, (reason, context)) in addrs_to_disconnect {
            internal.connected_clients.remove(&addr).unwrap();
            if let Some(context) = context {
                internal
                    .pending_rejection_confirm
                    .insert(addr.clone(), context);
            }
            disconnected.insert(addr, reason);
        }

        for addr in to_auth.keys() {
            assigned_addrs_in_auth.insert(addr.clone());
        }

        match &internal.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
        }

        #[cfg(feature = "store_unexpected")]
        internal
            .store_unexpected_errors
            .create_list_signal_sender
            .try_send(())
            .unwrap();

        internal
            .rejections_to_confirm_signal_sender
            .try_send(())
            .unwrap();

        internal.try_check_read_handler();

        ServerTickResult {
            received_messages,
            to_auth,
            disconnected,
            #[cfg(feature = "store_unexpected")]
            unexpected_errors,
        }
    }

    /// Server periodic tick end.
    ///
    /// It handles:
    /// - Unification of packages to be sent to clients.
    ///
    /// # Panics
    /// If is not called after [`Server::tick_start`]
    pub fn tick_end(&self) {
        let internal = &self.internal;
        {
            let mut tick_state = internal.tick_state.write().unwrap();
            if *tick_state != ServerTickState::TickEndPending {
                panic!(
                    "Invalid server tick state, next pending is {:?}",
                    tick_state
                );
            } else {
                *tick_state = ServerTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = internal.packet_registry.serialize(&ServerTickEndPacket);

        for client in internal.connected_clients.iter() {
            self.send_packet_serialized(&client, tick_packet_serialized.clone());
            client.packets_to_send_sender.try_send(None).unwrap();
        }
    }

    /// Connect a client.
    ///
    /// Should only be used with [`AddrToAuth`] that were created after the last server tick,
    /// if another tick server tick comes up, the [`addr_to_auth`] will not be valid.
    ///
    /// # Panics
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    pub fn authenticate(&self, addr: SocketAddr, addr_to_auth: AddrToAuth) {
        let internal = &self.internal;
        if internal.connected_clients.contains_key(&addr) {
            panic!("Addr is already connected.",)
        } else if !internal
            .assigned_addrs_in_auth
            .write()
            .unwrap()
            .remove(&addr)
        {
            panic!("Addr was not marked to be authenticated in the last server tick.",)
        } else {
            match &internal.authenticator_mode {
                AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                    auth_mode.remove_from_auth(&addr)
                }
                AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                    auth_mode.remove_from_auth(&addr)
                }
                AuthenticatorModeInternal::RequireTls(auth_mode) => {
                    auth_mode.remove_from_auth(&addr)
                }
            }
            .expect("Addr was not marked in the last tick to be possibly authenticated.");

            let (receiving_bytes_sender, receiving_bytes_receiver) = async_channel::unbounded();
            let (packets_to_send_sender, packets_to_send_receiver) = async_channel::unbounded();
            let (message_part_confirmation_sender, message_part_confirmation_receiver) =
                async_channel::unbounded();
            let (shared_socket_bytes_send_sender, shared_socket_bytes_send_receiver) =
                async_channel::unbounded();

            let now = Instant::now();

            let messaging = Mutex::new(ConnectedClientMessaging {
                cipher: ChaChaPoly1305::new(Key::from_slice(addr_to_auth.shared_key.as_bytes())),
                pending_confirmation: BTreeMap::new(),
                incoming_messages: MessagePartMap::new(
                    internal.messaging_properties.initial_next_message_part_id,
                ),
                tick_bytes_len: 0,
                last_received_message_instant: now,
                received_messages: Vec::new(),
                packet_loss_rtt_calculator: RttCalculator::new(
                    internal.messaging_properties.initial_latency,
                ),
                average_packet_loss_rtt: internal.messaging_properties.initial_latency,
                latency_monitor: DurationMonitor::filled_with(
                    internal.messaging_properties.initial_latency,
                    16,
                ),
            });

            let client = Arc::new(ConnectedClient {
                receiving_bytes_sender,
                packets_to_send_sender,
                message_part_confirmation_sender,
                shared_socket_bytes_send_sender,
                addr,
                messaging,
                last_messaging_write: RwLock::new(now),
                average_latency: RwLock::new(internal.messaging_properties.initial_latency),
                incoming_messages_total_size: RwLock::new(0),
            });

            let server_downgraded = Arc::downgrade(&internal);
            let client_downgraded = Arc::downgrade(&client);
            internal.create_async_task(async move {
                init::client::create_receiving_bytes_handler(
                    server_downgraded,
                    addr,
                    client_downgraded,
                    receiving_bytes_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&internal);
            let client_downgraded = Arc::downgrade(&client);
            let initial_next_message_part_id =
                internal.messaging_properties.initial_next_message_part_id;
            internal.create_async_task(async move {
                init::client::create_packets_to_send_handler(
                    server_downgraded,
                    client_downgraded,
                    packets_to_send_receiver,
                    initial_next_message_part_id,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&internal);
            internal.create_async_task(async move {
                init::client::create_message_part_confirmation_handler(
                    server_downgraded,
                    addr,
                    message_part_confirmation_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&internal);
            internal.create_async_task(async move {
                init::client::create_shared_socket_bytes_send_handler(
                    server_downgraded,
                    addr,
                    shared_socket_bytes_send_receiver,
                )
                .await;
            });

            internal.connected_clients.insert(addr, client);
        }
    }

    /// Refuses a client connection with justification.
    ///
    /// If you want to refuse a client, but without any justification, just ignore the `addrs_to_auth`.
    ///
    /// If that addr was already refused, the new message will replace the old message.
    ///
    /// Should only be used with [`AddrToAuth`] that were created after the last server tick,
    /// if another tick server tick comes up, the [`addr_to_auth`] will not be valid.
    ///
    /// # Panics
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    pub fn refuse(&self, addr: SocketAddr, message: SerializedPacketList) {
        let internal = &self.internal;
        if internal.connected_clients.contains_key(&addr) {
            panic!("Addr is already connected.",)
        } else if !internal
            .assigned_addrs_in_auth
            .write()
            .unwrap()
            .remove(&addr)
        {
            panic!("Addr was not marked to be authenticated in the last server tick.",)
        } else {
            internal.pending_rejection_confirm.insert(
                addr,
                JustifiedRejectionContext::from_serialized_list(Instant::now(), message),
            );
        }
    }

    /// Mark that client to be disconnected in the next tick.
    ///
    /// If there is a pending disconnection of that client, the new [`message`]
    /// will be ignored, and just the first message will be considered
    ///
    /// # Parameters
    ///
    /// * `message` - `ConnectedClient` message to send to the client, packet loss will be handled.
    /// If is None, no message will be sent to the client. That message has limited size.
    pub fn disconnect_from(&self, client: &ConnectedClient, message: Option<SerializedPacketList>) {
        let internal = &self.internal;
        let context = {
            if let Some(list) = message {
                Some(JustifiedRejectionContext::from_serialized_list(
                    Instant::now(),
                    list,
                ))
            } else {
                None
            }
        };
        internal
            .clients_to_disconnect_sender
            .try_send((
                client.addr.clone(),
                (ClientDisconnectReason::ManualDisconnect, context),
            ))
            .unwrap();
    }

    /// The messages of this addr will be ignored.
    ///
    /// If that client is already ignored, the reason will be replaced.
    ///
    /// If that client is temporary ignored, it will be permanently ignored.
    pub fn ignore_ip(&self, ip: IpAddr, reason: IgnoredAddrReason) {
        let internal = &self.internal;
        internal.ignore_ip(ip, reason);
    }

    /// The messages of this addr will be ignored, for the expected time, then,
    /// it will be cleared and the addr will be able to send messages for the server.
    ///
    /// If that client is already ignored, the reason will be replaced.
    pub fn ignore_ip_temporary(&self, ip: IpAddr, reason: IgnoredAddrReason, until_to: Instant) {
        let internal = &self.internal;
        internal.ignore_ip_temporary(ip, reason, until_to);
    }

    /// Removes the specified addr from the ignored list, even if it is temporary ignored.
    pub fn remove_ignore_ip(&self, ip: &IpAddr) {
        let internal = &self.internal;
        internal.remove_ignore_ip(ip);
    }

    /// # Returns
    /// Connected client if found.
    pub fn get_connected_client(
        &self,
        addr: &SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<SocketAddr, Arc<ConnectedClient>>> {
        let internal = &self.internal;
        internal.connected_clients.get(addr)
    }

    /// # Returns
    /// The amount of connected clients in the server
    pub fn connected_clients_size(&self) -> usize {
        let internal = &self.internal;
        internal.connected_clients.len()
    }

    /// # Returns
    /// Iterator with the clients connected to the server.
    pub fn connected_clients_iter(&self) -> dashmap::iter::Iter<SocketAddr, Arc<ConnectedClient>> {
        let internal = &self.internal;
        internal.connected_clients.iter()
    }

    /// Serializes, then store the packet to be sent to the client after the next server tick.
    ///
    /// If you need to send the same packet to multiple clients, see [`Server::send_packet_serialized`].
    ///
    /// # Parameters
    ///
    /// * `client` - `ConnectedClient` to which the packet will be sent.
    /// * `packet` - packet to be serialized and sent.
    ///
    /// # Panics
    ///
    /// If the packet serialization fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let server: &Server = ...;
    /// let addr: SocketAddr = ...;
    /// let client = server.get_connected_client(&addr).unwrap();
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// server.send_packet(&client, &packet);
    /// ```
    pub fn send_packet<P: Packet>(&self, client: &ConnectedClient, packet: &P) {
        let internal = &self.internal;
        let serialized = internal.packet_registry.serialize(packet);
        self.send_packet_serialized(client, serialized);
    }
    /// Store the packet to be sent to the client after the next server tick.
    ///
    /// Useful to send the same packet to multiple clients without re-serialize the packet.
    ///
    /// # Parameters
    ///
    /// * `client` - `ConnectedClient` to which the packet will be sent.
    /// * `packet` - packet to be sent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let server: &Server = ...;
    /// let addr: SocketAddr = ...;
    /// let client = server.get_connected_client(&addr).unwrap();
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// let packet_serialized = server.packet_registry().serialize(&packet);
    /// server.send_packet_serialized(&client, &packet_serialized);
    /// ```
    pub fn send_packet_serialized(
        &self,
        client: &ConnectedClient,
        packet_serialized: SerializedPacket,
    ) {
        client
            .packets_to_send_sender
            .try_send(Some(packet_serialized))
            .unwrap();
    }

    /// TODO:
    pub fn disconnect_detached(self) {
        todo!();
    }
}
