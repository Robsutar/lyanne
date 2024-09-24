//! Server exclusive module.
//!
//! Binding a server:
//!
//! ```rust,no_run
//! use lyanne::{packets::*, server::*, *};
//! use std::{net::SocketAddr, sync::Arc};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct HelloPacket {
//!    player_name: String,
//! }
//!
//! fn main() {
//!     let mut packet_registry = PacketRegistry::with_essential();
//!     packet_registry.add::<HelloPacket>();
//!
//!     let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
//!     let messaging_properties = Arc::new(MessagingProperties::default());
//!     let read_handler_properties = Arc::new(ReadHandlerProperties::default());
//!     let server_properties = Arc::new(ServerProperties::default());
//!     let authenticator_mode = AuthenticatorMode::NoCryptography;
//!
//!     let bind_handle = Server::bind(
//!         addr,
//!         Arc::new(packet_registry),
//!         messaging_properties,
//!         read_handler_properties,
//!         server_properties,
//!         authenticator_mode,
//!     );
//! }
//! ```
//!
//! Sending packet to clients:
//!
//! ```rust,no_run
//! use lyanne::{server::*, packets::Packet};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct MessagePacket {
//!    message: String,
//! }
//! fn inside_tick(server: &Server) {
//!     let packet = MessagePacket {
//!         message: "Foo!".to_owned(),
//!     };
//!
//!     for client in server.connected_clients_iter() {
//!         server.send_packet(&client, &packet);
//!     }
//! }
//! ```
//!
//! Authenticating clients:
//!
//! ```rust,no_run
//! use lyanne::{server::*, packets::Packet};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct HelloPacket {
//!    player_name: String,
//! }
//!
//! fn use_tick_result(server: &Server, tick_result: ServerTickResult) {
//!     for (auth_entry, message) in tick_result.to_auth {
//!         if let Ok(hello_packet) = message
//!             .to_packet_list()
//!             .remove(0)
//!             .packet
//!             .downcast::<HelloPacket>()
//!         {
//!             println!(
//!                 "Authenticating client {:?}, addr: {:?}",
//!                 hello_packet.player_name, auth_entry.addr()
//!             );
//!
//!             server.authenticate(
//!                 auth_entry,
//!                 server.packet_registry().empty_serialized_list(),
//!             );
//!         }
//!     }
//! }
//! ```
//!
//! Server tick management:
//!
//! ```rust,no_run
//! use lyanne::server::*;
//!
//! fn complete_tick(server: &Server) {
//!     let tick_result = server.tick_start();
//!
//!     use_tick_result(&server, tick_result);
//!     inside_tick(&server);
//!
//!     server.tick_end();
//! }
//! fn use_tick_result(server: &Server, tick_result: ServerTickResult) { /* */ }
//! fn inside_tick(server: &Server) { /* */ }
//! ```

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::KeyInit, ChaChaPoly1305, Key};
use dashmap::{DashMap, DashSet};

use crate::{
    internal::{
        messages::{DeserializedMessage, MessagePartMap, UDP_BUFFER_SIZE},
        node::{NodeInternal, NodeState, NodeType, PartnerMessaging},
        rt::{try_lock, AsyncRwLock, Mutex, TaskHandle, TaskRunner, UdpSocket},
        utils::{DurationMonitor, RttCalculator},
        JustifiedRejectionContext, MessageChannel,
    },
    packets::{
        Packet, PacketRegistry, SerializedPacket, SerializedPacketList, ServerTickEndPacket,
    },
    LimitedMessage, MessagingProperties, ReadHandlerProperties, MESSAGE_CHANNEL_SIZE,
};

#[cfg(feature = "store_unexpected")]
use crate::internal::node::StoreUnexpectedErrors;

pub use dashmap::{iter::Iter as DashIter, mapref::one::Ref as DashRef};

use crate::internal::auth::InnerAuth;
#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::internal::auth::InnerAuthTcpBased;

pub use crate::internal::node::Partner as ConnectedClient;
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
    /// The public key send operation is invalid. And the error code.
    InvalidPublicKeySend(u16),
    /// The client tried to authenticate, but it is already connected.
    AlreadyConnected,
    /// Some address tried to exchange keys with the server,
    /// but the pending authentication list was full.
    ///  
    /// See [`ServerProperties::max_pending_auth`].
    PendingAuthFull,
}

impl ReadClientBytesResult {
    /// # Returns
    /// `true` if the result is unexpected.
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
            ReadClientBytesResult::InvalidPublicKeySend(_) => true,
            ReadClientBytesResult::AlreadyConnected => true,
            ReadClientBytesResult::PendingAuthFull => true,
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

/// Properties to disconnect the clients from the server, notifying them.
pub struct GracefullyDisconnection {
    /// The client response timeout.
    pub timeout: Duration,
    /// The message.
    pub message: LimitedMessage,
}

/// The disconnection state of an specific client.
#[derive(Debug)]
pub enum ServerDisconnectClientState {
    /// The client received the message, and confirmed the server disconnection.
    Confirmed,
    /// The client did not respond in time.
    ConfirmationTimeout,
    /// Error sending the bytes of the client.
    SendIoError(io::Error),
    /// Error receiving the bytes of the client.
    ReceiveIoError(io::Error),
}

/// The disconnection state.
#[derive(Debug)]
pub enum ServerDisconnectState {
    /// The result of the message sent to the client warning about the server connection.
    ///
    /// See [`GracefullyDisconnection`].
    Confirmations(HashMap<SocketAddr, ServerDisconnectClientState>),
    /// Server did not notified the clients of the server close.
    WithoutReason,
}

/// General properties for the server management.
pub struct ServerProperties {
    // TODO: field not used in TCP based auth.
    pub pending_auth_packet_loss_interpretation: Duration,
    /// Limits the number of pending authentications.
    ///
    /// See [`ReadClientBytesResult::PendingAuthFull`].
    pub max_pending_auth: usize,
    /// If an addr sends an invalid message, its IP will be ignored for this duration.
    pub invalid_message_punishment: Option<Duration>,
}

impl Default for ServerProperties {
    fn default() -> Self {
        Self {
            pending_auth_packet_loss_interpretation: Duration::from_secs(3),
            max_pending_auth: usize::MAX,
            invalid_message_punishment: Some(Duration::from_secs(5)),
        }
    }
}
/// Result when calling [`Server::bind`].
pub struct BindResult {
    /// The bind server to handle tne next connections and tick management.
    pub server: Server,
}

/// Possible reasons why a bind was unsuccessful with [`Server::bind`].
#[derive(Debug)]
pub enum BindError {
    /// Packet registry has not registered the essential packets.
    MissingEssentialPackets,
    /// IO error on UDP socket binding.
    SocketBindError(io::Error),
    /// IO error on authenticator binding.
    AuthenticatorConnectIoError(io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BindError::MissingEssentialPackets => write!(
                f,
                "Packet registry has not registered the essential packets."
            ),
            BindError::SocketBindError(e) => write!(f, "Failed to bind UDP socket: {}", e),
            BindError::AuthenticatorConnectIoError(ref err) => {
                write!(f, "Authenticator connect IO error: {}", err)
            }
        }
    }
}

impl std::error::Error for BindError {}

/// Possible reasons why a authentication was unsuccessful with [`Server::try_authenticate`].
///
/// All reasons are related to wrong usage of [`AuthEntry`] and [`Server::try_authenticate`].
#[derive(Debug)]
pub enum BadAuthenticateUsageError {
    AlreadyConnected,
    NotMarkedToAuthenticate,
}

impl fmt::Display for BadAuthenticateUsageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BadAuthenticateUsageError::AlreadyConnected => write!(f, "Addr is already connected."),
            BadAuthenticateUsageError::NotMarkedToAuthenticate => write!(
                f,
                "Addr was not marked in the last tick to be possibly authenticated."
            ),
        }
    }
}

impl std::error::Error for BadAuthenticateUsageError {}

/// Server tick flow state.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerTickState {
    /// Next call should be [`Server::try_tick_start`].
    TickStartPending,
    /// Next call should be [`Server::try_tick_end`].
    TickEndPending,
}

#[cfg(feature = "store_unexpected")]
#[derive(Debug)]
/// Errors generated during connection.
pub enum UnexpectedError {
    /// While reading bytes from some addr.
    ///
    /// See [`ReadClientBytesResult::is_unexpected`]
    OfReadAddrBytes(SocketAddr, ReadClientBytesResult),
    /// While trying to accept clients from the tcp based authenticators.
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    OfTcpBasedHandlerAccept(SocketAddr, ReadClientBytesResult),
    /// Io error while trying to accept clients from the tcp based authenticators.
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    OfTcpBasedHandlerAcceptIoError(SocketAddr, io::Error),
}

/// The authentication entry of some not connected client.
///
/// Used to accept/refuse/ignore the authentication.
pub struct AuthEntry {
    addr: SocketAddr,
    addr_to_auth: AddrToAuth,
}

impl PartialEq for AuthEntry {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for AuthEntry {}

impl std::hash::Hash for AuthEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl AuthEntry {
    /// # Returns
    /// Socket address of this client.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}

/// Result when calling [`Server::try_tick_start`].
pub struct ServerTickResult {
    /// Received messages from the clients.
    ///
    /// The list (`Vec<DeserializedMessage>`) will never be empty.
    /// If some client did not sent a message since the last tick, it will not appear in this map.
    pub received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>>,
    /// Client to authenticate, and their authentication message.
    /// # Examples
    /// ```no_run
    /// use lyanne::{server::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct HelloPacket {
    ///     player_name: String,
    /// }
    ///
    /// fn example_usage(server: &Server) {
    ///     let tick_result: ServerTickResult = server.tick_start();
    ///     for (auth_entry, message) in tick_result.to_auth {
    ///         if let Ok(hello_packet) = message
    ///             .to_packet_list()
    ///             .remove(0)
    ///             .packet
    ///             .downcast::<HelloPacket>()
    ///         {
    ///             println!(
    ///                 "Authenticating client {:?}, addr: {:?}",
    ///                 hello_packet.player_name, auth_entry.addr()
    ///             );
    ///
    ///             server.authenticate(
    ///                 auth_entry,
    ///                 server.packet_registry().empty_serialized_list(),
    ///             );
    ///         } else {
    ///             // Discards the authentication, the client will not know explicitly the refuse.
    ///             // If is desired to send a justification to the client, see [`Server::try_refuse`]
    ///             println!(
    ///                 "Client {:?} did not sent a `HelloPacket`, it will not be authenticated",
    ///                 auth_entry.addr()
    ///             );
    ///         }
    ///     }
    /// }
    /// ```
    pub to_auth: HashMap<AuthEntry, DeserializedMessage>,
    /// Disconnected clients since the last tick, and the reason.
    pub disconnected: HashMap<SocketAddr, ClientDisconnectReason>,
    /// Errors emitted since the last server tick.
    #[cfg(feature = "store_unexpected")]
    pub unexpected_errors: Vec<UnexpectedError>,
}

struct ServerNode {
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
    pub store_unexpected_errors: StoreUnexpectedErrors<UnexpectedError>,

    authenticator_mode: AuthenticatorModeInternal,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    /// Actual state of server periodic tick flow.
    tick_state: RwLock<ServerTickState>,

    /// Properties for the internal server management.
    server_properties: Arc<ServerProperties>,

    /// Map of connected clients, keyed by their socket address.
    connected_clients: DashMap<SocketAddr, Arc<ConnectedClient>>,

    /// Set of ignored ips.
    ignored_ips: DashSet<IpAddr>,
    /// Map of temporarily ignored addresses with the time until they are ignored.
    temporary_ignored_ips: DashMap<IpAddr, Instant>,

    /// Lock-protected set of assigned addresses in authentication.
    assigned_addrs_in_auth: RwLock<HashSet<SocketAddr>>,

    /// Map of clients that were recently disconnected itself.
    recently_disconnected: DashMap<SocketAddr, Instant>,
    /// Map of pending rejection confirmations.
    pending_rejection_confirm: DashMap<SocketAddr, (JustifiedRejectionContext, Option<Instant>)>,
    /// Set of addresses asking for the rejection confirm.
    rejections_to_confirm: DashSet<SocketAddr>,

    state: AsyncRwLock<NodeState<(SocketAddr, Vec<u8>)>>,
}

impl ServerNode {
    fn ignore_ip(&self, ip: IpAddr) {
        self.temporary_ignored_ips.remove(&ip);
        self.ignored_ips.insert(ip);
    }

    fn ignore_ip_temporary(&self, ip: IpAddr, until_to: Instant) {
        self.ignored_ips.insert(ip);
        self.temporary_ignored_ips.insert(ip, until_to);
    }

    fn remove_ignore_ip(&self, ip: &IpAddr) {
        self.ignored_ips.remove(ip);
        self.temporary_ignored_ips.remove(ip);
    }

    fn try_check_read_handler(node: &Arc<NodeInternal<Self>>) {
        if let Ok(mut active_count) = node.read_handler_properties.active_count.try_write() {
            if *active_count < node.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&node);
                node.create_async_task(init::server::create_read_handler(downgraded_server));
            }
        }
    }

    async fn pre_read_next_bytes(
        socket: &Arc<UdpSocket>,
        read_timeout: Duration,
    ) -> io::Result<(SocketAddr, Vec<u8>)> {
        let pre_read_next_bytes_result: Result<io::Result<(SocketAddr, Vec<u8>)>, ()> =
            crate::internal::rt::timeout(read_timeout, async move {
                let mut buf = [0u8; UDP_BUFFER_SIZE];
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
        node: &NodeInternal<ServerNode>,
        tuple: (SocketAddr, Vec<u8>),
    ) -> ReadClientBytesResult {
        let node_type = &node.node_type;
        let (addr, bytes) = tuple;

        if bytes.len() < MESSAGE_CHANNEL_SIZE {
            return ReadClientBytesResult::InsufficientBytesLen;
        }

        if node_type.pending_rejection_confirm.contains_key(&addr) {
            if bytes[0] == MessageChannel::REJECTION_CONFIRM {
                node_type.pending_rejection_confirm.remove(&addr);
                return ReadClientBytesResult::DoneDisconnectConfirm;
            } else {
                return ReadClientBytesResult::PendingDisconnectConfirm;
            }
        }

        if bytes[0] == MessageChannel::REJECTION_JUSTIFICATION {
            if node_type.recently_disconnected.contains_key(&addr) {
                node_type.rejections_to_confirm.insert(addr);
                return ReadClientBytesResult::RecentClientDisconnectConfirm;
            }
        }

        match &node_type.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                NoCryptographyAuth::read_next_bytes(&node, addr, bytes, auth_mode).await
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.read_next_bytes(&node, addr, bytes).await
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.read_next_bytes(&node, addr, bytes).await
            }
        }
    }
}

impl NodeType for ServerNode {
    type Skt = (SocketAddr, Vec<u8>);

    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>> {
        &self.state
    }
}

/// Connected server.
///
/// # Info
/// **See more information about the server creation and management in [`server`](crate::server) module.**
pub struct Server {
    internal: Arc<NodeInternal<ServerNode>>,
}

impl Server {
    /// Bind a [`UdpSocket´], to create a new Server instance.
    ///
    /// Additional sockets may be used depending on the authentication mode.
    pub fn bind(
        addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        server_properties: Arc<ServerProperties>,
        authenticator_mode: AuthenticatorMode,
        #[cfg(any(feature = "rt_tokio", feature = "rt_async_executor"))]
        runtime: crate::internal::rt::Runtime,
    ) -> TaskHandle<Result<BindResult, BindError>> {
        #[cfg(any(feature = "rt_tokio", feature = "rt_async_executor"))]
        let task_runner = Arc::new(TaskRunner { runtime });

        #[cfg(not(any(feature = "rt_tokio", feature = "rt_async_executor")))]
        let task_runner = Arc::new(TaskRunner {});

        let task_runner_exit = Arc::clone(&task_runner);

        let bind_result_body = async move {
            if !packet_registry.check_essential() {
                return Err(BindError::MissingEssentialPackets);
            }

            let socket = match UdpSocket::bind(addr).await {
                Ok(socket) => Arc::new(socket),
                Err(e) => return Err(BindError::SocketBindError(e)),
            };

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

            let tasks_keeper_handle = task_runner.spawn(init::server::create_async_tasks_keeper(
                tasks_keeper_receiver,
            ));
            let tasks_keeper_handle = Mutex::new(Some(tasks_keeper_handle));

            #[cfg(feature = "store_unexpected")]
            let (store_unexpected_errors, store_unexpected_errors_create_list_signal_receiver) =
                StoreUnexpectedErrors::new();

            let mut authenticator_mode_build = authenticator_mode.build();

            let server = Arc::new(NodeInternal {
                tasks_keeper_sender,
                tasks_keeper_handle,
                packet_registry,
                messaging_properties,
                read_handler_properties,
                task_runner,
                node_type: ServerNode {
                    clients_to_auth_sender,
                    clients_to_disconnect_sender,

                    rejections_to_confirm_signal_sender,
                    pending_rejection_confirm_resend_sender,

                    clients_to_auth_receiver,

                    clients_to_disconnect_receiver,

                    #[cfg(feature = "store_unexpected")]
                    store_unexpected_errors,

                    authenticator_mode: authenticator_mode_build.take_authenticator_mode_internal(),
                    socket,

                    tick_state: RwLock::new(ServerTickState::TickStartPending),

                    server_properties,
                    connected_clients: DashMap::new(),
                    ignored_ips: DashSet::new(),
                    temporary_ignored_ips: DashMap::new(),

                    assigned_addrs_in_auth: RwLock::new(HashSet::new()),
                    recently_disconnected: DashMap::new(),
                    pending_rejection_confirm: DashMap::new(),
                    rejections_to_confirm: DashSet::new(),

                    state: AsyncRwLock::new(NodeState::Active),
                },
            });

            if let Err(e) = authenticator_mode_build.apply(&server).await {
                return Err(BindError::AuthenticatorConnectIoError(e));
            }

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

        task_runner_exit.spawn(bind_result_body)
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
        &self.internal.node_type.server_properties
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
    /// # Errors
    /// If [`Server::try_tick_end`] call is pending. That is, the cycle must be:
    /// - [`Server::try_tick_start`]
    /// - [`Server::try_tick_end`]
    /// - [`Server::try_tick_start`]
    /// - [`Server::try_tick_end`]
    /// - ...
    pub fn try_tick_start(&self) -> Result<ServerTickResult, ()> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        {
            let mut tick_state = node_type.tick_state.write().unwrap();
            if *tick_state != ServerTickState::TickStartPending {
                return Err(());
            } else {
                *tick_state = ServerTickState::TickEndPending;
            }
        }

        let now = Instant::now();

        let mut assigned_addrs_in_auth = node_type.assigned_addrs_in_auth.write().unwrap();
        let dispatched_assigned_addrs_in_auth = std::mem::take(&mut *assigned_addrs_in_auth);

        match &node_type.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.tick_start(internal, now, dispatched_assigned_addrs_in_auth);
            }
        }

        #[cfg(feature = "store_unexpected")]
        let unexpected_errors = match internal
            .node_type
            .store_unexpected_errors
            .error_list_receiver
            .try_recv()
        {
            Ok(list) => list,
            Err(_) => Vec::new(),
        };

        node_type.recently_disconnected.retain(|_, received_time| {
            now - *received_time < internal.messaging_properties.timeout_interpretation
        });

        node_type.temporary_ignored_ips.retain(|addr, until_to| {
            if now < *until_to {
                true
            } else {
                node_type.ignored_ips.remove(addr);
                false
            }
        });

        let mut received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>> = HashMap::new();
        let mut to_auth: HashMap<AuthEntry, DeserializedMessage> = HashMap::new();
        let mut disconnected: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

        let mut addrs_to_disconnect: HashMap<
            SocketAddr,
            (ClientDisconnectReason, Option<JustifiedRejectionContext>),
        > = HashMap::new();

        while let Ok((addr, (addr_to_auth, message))) =
            node_type.clients_to_auth_receiver.try_recv()
        {
            to_auth.insert(AuthEntry { addr, addr_to_auth }, message);
        }

        while let Ok((addr, reason)) = node_type.clients_to_disconnect_receiver.try_recv() {
            if !addrs_to_disconnect.contains_key(&addr) {
                addrs_to_disconnect.insert(addr, reason);
            }
        }

        'l1: for client in node_type.connected_clients.iter() {
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

        node_type
            .pending_rejection_confirm
            .retain(|_, (context, _)| {
                now - context.rejection_instant
                    < internal
                        .messaging_properties
                        .disconnect_reason_resend_cancel
            });
        for tuple in node_type.pending_rejection_confirm.iter() {
            let (_, last_sent_time) = tuple.value();
            if let Some(last_sent_time) = last_sent_time {
                if now - *last_sent_time
                    < internal.messaging_properties.disconnect_reason_resend_delay
                {
                    continue;
                }
            }
            node_type
                .pending_rejection_confirm_resend_sender
                .try_send(tuple.key().clone())
                .unwrap();
        }

        for (addr, (reason, context)) in addrs_to_disconnect {
            node_type.connected_clients.remove(&addr).unwrap();
            if let Some(context) = context {
                node_type
                    .pending_rejection_confirm
                    .insert(addr, (context, None));
            }
            disconnected.insert(addr, reason);
        }

        for auth_entry in to_auth.keys() {
            assigned_addrs_in_auth.insert(*auth_entry.addr());
        }

        match &node_type.authenticator_mode {
            AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
            #[cfg(feature = "auth_tcp")]
            AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
            #[cfg(feature = "auth_tls")]
            AuthenticatorModeInternal::RequireTls(auth_mode) => {
                auth_mode.call_tick_start_signal();
            }
        }

        #[cfg(feature = "store_unexpected")]
        internal
            .node_type
            .store_unexpected_errors
            .create_list_signal_sender
            .try_send(())
            .unwrap();

        node_type
            .rejections_to_confirm_signal_sender
            .try_send(())
            .unwrap();

        ServerNode::try_check_read_handler(internal);

        Ok(ServerTickResult {
            received_messages,
            to_auth,
            disconnected,
            #[cfg(feature = "store_unexpected")]
            unexpected_errors,
        })
    }

    /// Panic version of [`Server::try_tick_start`].
    ///
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
    #[cfg(not(feature = "no_panics"))]
    pub fn tick_start(&self) -> ServerTickResult {
        self.try_tick_start().expect("Invalid server tick state.")
    }

    /// Server periodic tick end.
    ///
    /// It handles:
    /// - Unification of packages to be sent to clients.
    ///
    /// # Errors
    /// If is not called after [`Server::try_tick_start`]
    pub fn try_tick_end(&self) -> Result<(), ()> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        {
            let mut tick_state = node_type.tick_state.write().unwrap();
            if *tick_state != ServerTickState::TickEndPending {
                return Err(());
            } else {
                *tick_state = ServerTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = internal
            .packet_registry
            .try_serialize(&ServerTickEndPacket)
            .unwrap();

        for client in node_type.connected_clients.iter() {
            self.send_packet_serialized(&client, tick_packet_serialized.clone());
            client.packets_to_send_sender.try_send(None).unwrap();
        }

        Ok(())
    }

    /// Panic version of [`Server::try_tick_end`].
    ///
    /// Server periodic tick end.
    ///
    /// It handles:
    /// - Unification of packages to be sent to clients.
    ///
    /// # Panics
    /// If is not called after [`Server::tick_start`]
    #[cfg(not(feature = "no_panics"))]
    pub fn tick_end(&self) {
        self.try_tick_end().expect("Invalid server tick state.")
    }

    /// Connect a client.
    ///
    /// Should only be used with [`AuthEntry`] that were created after the last server tick start,
    /// if another tick server tick comes up, the `auth_entry` will not be valid.
    ///
    /// # Errors
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    ///
    /// All panics are related to the bad usage of this function and of the [`AuthEntry`].
    pub fn try_authenticate(
        &self,
        auth_entry: AuthEntry,
        initial_message: SerializedPacketList,
    ) -> Result<(), BadAuthenticateUsageError> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        let addr = auth_entry.addr;
        let addr_to_auth = auth_entry.addr_to_auth;
        if node_type.connected_clients.contains_key(&addr) {
            Err(BadAuthenticateUsageError::AlreadyConnected)
        } else if !node_type
            .assigned_addrs_in_auth
            .write()
            .unwrap()
            .remove(&addr)
        {
            Err(BadAuthenticateUsageError::NotMarkedToAuthenticate)
        } else {
            match &node_type.authenticator_mode {
                AuthenticatorModeInternal::NoCryptography(auth_mode) => {
                    auth_mode.remove_from_auth(&addr)
                }
                #[cfg(feature = "auth_tcp")]
                AuthenticatorModeInternal::RequireTcp(auth_mode) => {
                    auth_mode.remove_from_auth(&addr)
                }
                #[cfg(feature = "auth_tls")]
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

            let initial_next_message_part_id =
                internal.messaging_properties.initial_next_message_part_id + 1;

            let messaging = PartnerMessaging {
                pending_confirmation: BTreeMap::new(),
                incoming_messages: MessagePartMap::new(initial_next_message_part_id),
                tick_bytes_len: 0,
                last_received_message_instant: now,
                received_messages: Vec::new(),
                packet_loss_rtt_calculator: RttCalculator::new(
                    internal.messaging_properties.initial_latency,
                ),
                average_packet_loss_rtt: internal.messaging_properties.initial_latency,
                latency_monitor: DurationMonitor::try_filled_with(
                    internal.messaging_properties.initial_latency,
                    16,
                )
                .unwrap(),
            };

            let client = Arc::new(ConnectedClient {
                receiving_bytes_sender,
                packets_to_send_sender,
                message_part_confirmation_sender,
                shared_socket_bytes_send_sender,
                addr,
                inner_auth: addr_to_auth.inner_auth,
                messaging: Mutex::new(messaging),
                last_messaging_write: RwLock::new(now),
                average_latency: RwLock::new(internal.messaging_properties.initial_latency),
                incoming_messages_total_size: RwLock::new(0),
            });

            init::client::push_completed_message_tick(
                &internal,
                &client,
                &mut client.messaging.try_lock().unwrap(),
                &client.shared_socket_bytes_send_sender,
                initial_next_message_part_id - 1,
                initial_message,
            );

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

            node_type.connected_clients.insert(addr, client);

            Ok(())
        }
    }

    /// Panic version of [`Server::try_authenticate`].
    ///
    /// Connect a client.
    ///
    /// Should only be used with [`AuthEntry`] that were created after the last server tick start,
    /// if another tick server tick comes up, the `auth_entry` will not be valid.
    ///
    /// # Panics
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    ///
    /// All panics are related to the bad usage of this function and of the [`AuthEntry`].
    #[cfg(not(feature = "no_panics"))]
    pub fn authenticate(&self, auth_entry: AuthEntry, initial_message: SerializedPacketList) {
        self.try_authenticate(auth_entry, initial_message).unwrap()
    }

    /// Refuses a client connection with justification.
    ///
    /// If you want to refuse a client, but without any justification, just ignore the [`AuthEntry`].
    ///
    /// If that addr was already refused, the new message will replace the old message.
    ///
    /// Should only be used with [`AuthEntry`] that were created after the last server tick,
    /// if another tick server tick comes up, the [`AuthEntry`] will not be valid.
    ///
    /// # Errors
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    ///
    /// All panics are related to the bad usage of this function and of the [`AuthEntry`].
    pub fn try_refuse(
        &self,
        auth_entry: AuthEntry,
        message: LimitedMessage,
    ) -> Result<(), BadAuthenticateUsageError> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        let addr = auth_entry.addr;
        let addr_to_auth = auth_entry.addr_to_auth;
        if node_type.connected_clients.contains_key(&addr) {
            Err(BadAuthenticateUsageError::AlreadyConnected)
        } else if !node_type
            .assigned_addrs_in_auth
            .write()
            .unwrap()
            .remove(&addr)
        {
            Err(BadAuthenticateUsageError::NotMarkedToAuthenticate)
        } else {
            node_type.pending_rejection_confirm.insert(
                addr,
                (
                    addr_to_auth
                        .inner_auth
                        .rejection_of(Instant::now(), message),
                    None,
                ),
            );

            Ok(())
        }
    }

    /// Panic version of [`Server::try_refuse`].
    ///
    /// Refuses a client connection with justification.
    ///
    /// If you want to refuse a client, but without any justification, just ignore the [`AuthEntry`].
    ///
    /// If that addr was already refused, the new message will replace the old message.
    ///
    /// Should only be used with [`AuthEntry`] that were created after the last server tick,
    /// if another tick server tick comes up, the [`AuthEntry`] will not be valid.
    ///
    /// # Panics
    /// - if addr is already connected.
    /// - if addr was not marked in the last tick to be possibly authenticated.
    ///
    /// All panics are related to the bad usage of this function and of the [`AuthEntry`].
    #[cfg(not(feature = "no_panics"))]
    pub fn refuse(&self, auth_entry: AuthEntry, message: LimitedMessage) {
        self.try_refuse(auth_entry, message).unwrap()
    }

    /// Mark that client to be disconnected in the next tick.
    ///
    /// If there is a pending disconnection of that client, the new `message`
    /// will be ignored, and just the first message will be considered
    ///
    /// # Parameters
    ///
    /// * `message` - `ConnectedClient` message to send to the client, packet loss will be handled.
    /// If is None, no message will be sent to the client. That message has limited size.
    pub fn disconnect_from(&self, client: &ConnectedClient, message: Option<LimitedMessage>) {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        let context = {
            if let Some(message) = message {
                Some(client.inner_auth.rejection_of(Instant::now(), message))
            } else {
                None
            }
        };
        node_type
            .clients_to_disconnect_sender
            .try_send((
                client.addr,
                (ClientDisconnectReason::ManualDisconnect, context),
            ))
            .unwrap();
    }

    /// The messages of this addr will be ignored.
    ///
    /// If that client is already ignored, the reason will be replaced.
    ///
    /// If that client is temporary ignored, it will be permanently ignored.
    pub fn ignore_ip(&self, ip: IpAddr) {
        let node_type = &self.internal.node_type;
        node_type.ignore_ip(ip);
    }

    /// The messages of this addr will be ignored, for the expected time, then,
    /// it will be cleared and the addr will be able to send messages for the server.
    ///
    /// If that client is already ignored, the reason will be replaced.
    pub fn ignore_ip_temporary(&self, ip: IpAddr, until_to: Instant) {
        let node_type = &self.internal.node_type;
        node_type.ignore_ip_temporary(ip, until_to);
    }

    /// Removes the specified addr from the ignored list, even if it is temporary ignored.
    pub fn remove_ignore_ip(&self, ip: &IpAddr) {
        let node_type = &self.internal.node_type;
        node_type.remove_ignore_ip(ip);
    }

    /// # Returns
    /// Connected client if found.
    pub fn get_connected_client(
        &self,
        addr: &SocketAddr,
    ) -> Option<DashRef<SocketAddr, Arc<ConnectedClient>>> {
        let node_type = &self.internal.node_type;
        node_type.connected_clients.get(addr)
    }

    /// # Returns
    /// The amount of connected clients in the server
    pub fn connected_clients_size(&self) -> usize {
        let node_type = &self.internal.node_type;
        node_type.connected_clients.len()
    }

    /// # Returns
    /// Iterator with the clients connected to the server.
    pub fn connected_clients_iter(&self) -> DashIter<SocketAddr, Arc<ConnectedClient>> {
        let node_type = &self.internal.node_type;
        node_type.connected_clients.iter()
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
    /// # Errors
    ///
    /// If the packet serialization fails, or if `P` was not registered in PacketRegistry.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use lyanne::{server::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(server: &Server, addr: &SocketAddr) {
    ///     let client = server.get_connected_client(&addr).expect("Client not found.");
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     server.try_send_packet(&client, &packet).unwrap();
    /// }
    /// ```
    pub fn try_send_packet<P: Packet>(
        &self,
        client: &ConnectedClient,
        packet: &P,
    ) -> Result<(), io::Error> {
        let internal = &self.internal;
        let serialized = internal.packet_registry.try_serialize(packet)?;
        self.send_packet_serialized(client, serialized);

        Ok(())
    }

    /// Panic version of [`Server::try_send_packet`].
    ///
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
    /// If the packet serialization fails, or if `P` was not registered in PacketRegistry.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use lyanne::{server::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(server: &Server, addr: &SocketAddr) {
    ///     let client = server.get_connected_client(&addr).expect("Client not found.");
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     server.send_packet(&client, &packet);
    /// }
    /// ```
    #[cfg(not(feature = "no_panics"))]
    pub fn send_packet<P: Packet>(&self, client: &ConnectedClient, packet: &P) {
        self.try_send_packet(client, packet)
            .expect("Failed to send packet.");
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
    /// use std::net::SocketAddr;
    /// use lyanne::{server::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(server: &Server, addr: &SocketAddr) {
    ///     let client = server.get_connected_client(&addr).expect("Client not found.");
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     let packet_serialized = server.packet_registry().serialize(&packet);
    ///     server.send_packet_serialized(&client, packet_serialized);
    /// }
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

    /// Disconnect the server from the clients gracefully if there is some message.
    ///
    /// # Examples
    /// ```no_run
    /// use std::time::Duration;
    /// use lyanne::{server::*, packets::{Packet, SerializedPacketList}, LimitedMessage};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    ///
    /// async fn example_usage(server: Server) {
    ///     let message = LimitedMessage::new(SerializedPacketList::single(
    ///         server.packet_registry().serialize(&MessagePacket {
    ///             message: "We finished here...".to_owned(),
    ///         }),
    ///     ));
    ///     let state = server
    ///         .disconnect(Some(GracefullyDisconnection {
    ///             message,
    ///             timeout: Duration::from_secs(3),
    ///         }))
    ///         .await;
    ///     println!("Server disconnected itself: {:?}", state);
    /// }
    /// ```
    pub fn disconnect(
        self,
        disconnection: Option<GracefullyDisconnection>,
    ) -> TaskHandle<ServerDisconnectState> {
        let tasks_keeper_exit = Arc::clone(&self.internal.task_runner);
        let tasks_keeper = Arc::clone(&self.internal.task_runner);
        tasks_keeper_exit.spawn(async move {
            let (received_bytes_sender, received_bytes_receiver) = async_channel::unbounded();
            NodeState::set_inactive(&self.internal.node_type.state, received_bytes_sender).await;

            let tasks_keeper_handle = self
                .internal
                .tasks_keeper_handle
                .lock()
                .await
                .take()
                .unwrap();

            if let Some(disconnection) = disconnection {
                let mut confirmations = HashMap::<SocketAddr, ServerDisconnectClientState>::new();
                let mut confirmations_pending =
                    HashMap::<SocketAddr, (Duration, Instant, JustifiedRejectionContext)>::new();

                let timeout_interpretation = disconnection.timeout;

                {
                    let now = Instant::now();
                    for connected_client in self.connected_clients_iter() {
                        let addr = connected_client.key().clone();
                        let packet_loss_timeout = connected_client
                            .messaging
                            .lock()
                            .await
                            .average_packet_loss_rtt
                            .min(timeout_interpretation);

                        confirmations_pending.insert(
                            addr,
                            (
                                packet_loss_timeout,
                                now,
                                connected_client.inner_auth.rejection_of(
                                    Instant::now(),
                                    LimitedMessage::clone(&disconnection.message),
                                ),
                            ),
                        );
                    }
                }

                let socket = Arc::clone(&self.internal.node_type.socket);

                let rejection_confirm_bytes = &vec![MessageChannel::REJECTION_CONFIRM];

                while !confirmations_pending.is_empty() {
                    let now = Instant::now();

                    let mut min_try_read_time = Duration::MAX;
                    let mut addrs_confirmed =
                        HashMap::<SocketAddr, ServerDisconnectClientState>::new();

                    for (addr, (packet_loss_timeout, last_sent_time, rejection_context)) in
                        confirmations_pending.iter_mut()
                    {
                        if now - rejection_context.rejection_instant > timeout_interpretation {
                            addrs_confirmed
                                .insert(*addr, ServerDisconnectClientState::ConfirmationTimeout);
                            continue;
                        }

                        let last_sent_time_copy = *last_sent_time;
                        let packet_loss_timeout_copy = *packet_loss_timeout;
                        let time_diff = now - last_sent_time_copy;

                        if now == last_sent_time_copy || time_diff >= packet_loss_timeout_copy {
                            *last_sent_time = now;
                            if let Err(e) = socket
                                .send_to(&rejection_context.finished_bytes, addr)
                                .await
                            {
                                addrs_confirmed
                                    .insert(*addr, ServerDisconnectClientState::SendIoError(e));
                            } else {
                                min_try_read_time = Duration::ZERO;
                            }
                        } else {
                            let remaining_to_resend = packet_loss_timeout_copy - time_diff;
                            if remaining_to_resend < min_try_read_time {
                                min_try_read_time = remaining_to_resend;
                            }
                        }
                    }

                    for (addr, state) in addrs_confirmed {
                        confirmations_pending.remove(&addr);
                        confirmations.insert(addr, state);
                    }

                    if confirmations_pending.is_empty() {
                        break;
                    }

                    let pre_read_next_bytes_result = {
                        if let Ok(result) = received_bytes_receiver.try_recv() {
                            Ok(result)
                        } else {
                            ServerNode::pre_read_next_bytes(&socket, min_try_read_time).await
                        }
                    };

                    match pre_read_next_bytes_result {
                        Ok((addr, result)) => {
                            if &result == rejection_confirm_bytes {
                                if let Some(_) = confirmations_pending.remove(&addr) {
                                    confirmations
                                        .insert(addr, ServerDisconnectClientState::Confirmed);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                        Err(e) => {
                            for (addr, _) in confirmations_pending {
                                confirmations.insert(
                                    addr,
                                    ServerDisconnectClientState::ReceiveIoError(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("Error trying read data from udp socket: {}", e),
                                    )),
                                );
                            }
                            break;
                        }
                    }
                }

                let _ = tasks_keeper.cancel(tasks_keeper_handle).await;
                drop(self);

                ServerDisconnectState::Confirmations(confirmations)
            } else {
                let _ = tasks_keeper.cancel(tasks_keeper_handle).await;
                drop(self);

                ServerDisconnectState::WithoutReason
            }
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        NodeInternal::on_holder_drop(&self.internal);
    }
}
