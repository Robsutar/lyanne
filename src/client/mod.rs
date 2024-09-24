//! Client exclusive module.
//!
//! Connecting a client:
//!
//! ```rust,no_run
//! use std::{net::SocketAddr, sync::Arc, time::Duration};
//! use lyanne::{client::*, packets::*, *};
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
//!     let remote_addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
//!     let messaging_properties = Arc::new(MessagingProperties::default());
//!     let read_handler_properties = Arc::new(ReadHandlerProperties::default());
//!     let client_properties = Arc::new(ClientProperties::default());
//!     let authenticator_mode = AuthenticatorMode::NoCryptography(AuthenticationProperties {
//!         message: LimitedMessage::new(SerializedPacketList::single(packet_registry.serialize(
//!             &HelloPacket {
//!                 player_name: "Josh".to_owned(),
//!             },
//!         ))),
//!         timeout: Duration::from_secs(10),
//!     });
//!
//!     let connect_handle = Client::connect(
//!         remote_addr,
//!         Arc::new(packet_registry),
//!         messaging_properties,
//!         read_handler_properties,
//!         client_properties,
//!         authenticator_mode,
//!     );
//! }
//! ```
//! Sending packet to server:
//!
//! ```rust,no_run
//! use lyanne::{client::*, packets::Packet};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct MessagePacket {
//!    message: String,
//! }
//!
//! fn inside_tick(client: &Client) {
//!     let packet = MessagePacket {
//!         message: "Bar?".to_owned(),
//!     };
//!
//!     client.send_packet(&packet);
//! }
//! ```
//!
//! Client tick management:
//!
//! ```rust,no_run
//! use lyanne::client::*;
//!
//! fn tick_check(client: &Client) {
//!     match client.tick_start() {
//!         ClientTickResult::ReceivedMessage(tick_result) => {
//!             use_tick_result(&client, tick_result);
//!             inside_tick(&client);
//!             client.tick_after_message();
//!         }
//!         ClientTickResult::Disconnected => {
//!             println!(
//!                 "Client disconnected, reason: {:?}",
//!                 client.take_disconnect_reason().unwrap()
//!             );
//!         }
//!         _ => (),
//!     }
//! }
//!
//! fn use_tick_result(client: &Client, tick_result: ReceivedMessageClientTickResult) { /* */ }
//! fn inside_tick(client: &Client) { /* */ }
//!
//! ```

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    internal::{
        auth::InnerAuth,
        messages::{DeserializedMessage, PUBLIC_KEY_SIZE, UDP_BUFFER_SIZE},
        node::{NodeInternal, NodeState, NodeType, PartnerMessaging},
        rt::{try_lock, AsyncRwLock, TaskHandle, TaskRunner, UdpSocket},
        MessageChannel,
    },
    packets::{ClientTickEndPacket, Packet, PacketRegistry, SerializedPacket},
    LimitedMessage, MessagingProperties, ReadHandlerProperties, MESSAGE_CHANNEL_SIZE,
};

#[cfg(feature = "store_unexpected")]
use crate::internal::node::StoreUnexpectedErrors;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::internal::auth::InnerAuthTcpBased;

pub use crate::internal::node::Partner as ConnectedServer;
pub use auth::*;
use init::*;

mod auth;
mod init;

/// Possible results when receiving bytes by the server
#[derive(Debug)]
pub enum ReadServerBytesResult {
    /// Bytes were successfully received from the server.
    ServerReceivedBytes,
    /// The server has exceeded the maximum tick byte length.
    ///
    /// See [`MessagingProperties::max_tick_bytes_len`].
    ServerMaxTickByteLenOverflow,
}

impl ReadServerBytesResult {
    /// # Returns
    /// `true` if the result is unexpected.
    pub fn is_unexpected(&self) -> bool {
        match self {
            ReadServerBytesResult::ServerReceivedBytes => false,
            ReadServerBytesResult::ServerMaxTickByteLenOverflow => true,
        }
    }
}

/// Possible reasons to be disconnected from the server
#[derive(Debug)]
pub enum ServerDisconnectReason {
    /// Server was disconnected due to a timeout waiting for message confirmation.
    PendingMessageConfirmationTimeout,
    /// Server was disconnected because it did not receive messages within the expected time frame.
    MessageReceiveTimeout,
    /// Server was disconnected due to a timeout while trying to acquire a write lock.
    WriteUnlockTimeout,
    /// Server was disconnected due to invalid protocol communication.
    InvalidProtocolCommunication,
    /// Server was disconnected because of an error while sending bytes.
    ByteSendError(io::Error),
    /// Server was manually disconnected.
    ManualDisconnect,
    /// Server disconnected itself.
    DisconnectRequest(DeserializedMessage),
}

/// General properties for the client management.
pub struct ClientProperties {
    /// Time to interpret that the server may not have received the packet because of packet loss.
    pub auth_packet_loss_interpretation: Duration,
}

impl Default for ClientProperties {
    fn default() -> Self {
        Self {
            auth_packet_loss_interpretation: Duration::from_secs(3),
        }
    }
}

/// Client tick flow state.
#[derive(Debug, PartialEq, Eq)]
enum ClientTickState {
    /// Next call should be [`Client::tick_start`].
    TickStartPending,
    /// Next call should be [`Client::tick_end`].
    TickAfterMessagePending,
}

#[cfg(feature = "store_unexpected")]
#[derive(Debug)]
/// Errors generated during connection.
pub enum UnexpectedError {
    /// While reading bytes from the server.
    ///
    /// See [`ReadServerBytesResult::is_unexpected`]
    OfReadServerBytes(ReadServerBytesResult),
}

/// Message received from the server what represents a server tick.
#[derive(Debug)]
pub struct ReceivedMessageClientTickResult {
    /// The message.
    pub message: DeserializedMessage,
    /// Errors emitted since the last server message/tick.
    #[cfg(feature = "store_unexpected")]
    pub unexpected_errors: Vec<UnexpectedError>,
}

/// Result when calling [`Client::try_tick_start`]
#[derive(Debug)]
pub enum ClientTickResult {
    /// Message received from the server, see [`ReceivedMessageClientTickResult`].
    ReceivedMessage(ReceivedMessageClientTickResult),
    /// Message is pending from the server.
    PendingMessage,
    /// The client was disconnected from the server.
    ///
    /// After this is returned by the tick, is possible to use [`Client::take_disconnect_reason`]
    Disconnected,
    /// The write lock could not be acquired.
    WriteLocked,
}

/// Properties to disconnect the client from the server, notifying the server.
pub struct GracefullyDisconnection {
    /// The message.
    pub message: LimitedMessage,
    /// The server response timeout.
    pub timeout: Duration,
}

/// The disconnection state.
#[derive(Debug)]
pub enum ClientDisconnectState {
    /// The server received the message, and confirmed the client disconnection.
    Confirmed,
    /// The server did not respond in time.
    ConfirmationTimeout,
    /// No disconnection message was sent to the server.
    WithoutReason,
    /// Error sending the bytes of the server.
    SendIoError(io::Error),
    /// Error receiving the bytes of the server.
    ReceiveIoError(io::Error),
    /// The client is already disconnected.
    ///
    /// - (ServerDisconnectReason) if the reason of the disconnection was not taken.
    /// - None if the reason of the disconnection was already taken.
    AlreadyDisconnected(Option<ServerDisconnectReason>),
}

/// Properties of the client.
struct ClientNode {
    /// Sender for addresses to be disconnected.
    reason_to_disconnect_sender: async_channel::Sender<ServerDisconnectReason>,
    /// Receiver for addresses to be disconnected.
    reason_to_disconnect_receiver: async_channel::Receiver<ServerDisconnectReason>,

    #[cfg(feature = "store_unexpected")]
    store_unexpected_errors: StoreUnexpectedErrors<UnexpectedError>,

    authentication_mode: ConnectedAuthenticatorMode,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    /// Actual state of client periodic tick flow.
    tick_state: RwLock<ClientTickState>,

    /// Properties for the internal client management.
    client_properties: Arc<ClientProperties>,

    /// Connected server.
    connected_server: Arc<ConnectedServer>,

    /// Reason that caused the connection finish.
    ///
    /// If equals to [`Option::None`], the client was disconnected.
    /// If inner [`Option::Some`] equals to [`Option::None`], the disconnect reason was taken.
    disconnect_reason: RwLock<Option<Option<ServerDisconnectReason>>>,

    state: AsyncRwLock<NodeState<Vec<u8>>>,
}

impl ClientNode {
    fn try_check_read_handler(node: &Arc<NodeInternal<Self>>) {
        if let Ok(mut active_count) = node.read_handler_properties.active_count.try_write() {
            if *active_count < node.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&node);
                node.create_async_task(async move {
                    client::create_read_handler(downgraded_server).await;
                });
            }
        }
    }

    async fn pre_read_next_bytes(
        socket: &Arc<UdpSocket>,
        read_timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let pre_read_next_bytes_result: Result<io::Result<Vec<u8>>, ()> =
            crate::internal::rt::timeout(read_timeout, async move {
                let mut buf = [0u8; UDP_BUFFER_SIZE];
                let len = socket.recv(&mut buf).await?;
                Ok(buf[..len].to_vec())
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

    async fn read_next_bytes(node: &NodeInternal<Self>, bytes: Vec<u8>) -> ReadServerBytesResult {
        let mut messaging = node.node_type.connected_server.messaging.lock().await;
        // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
        messaging.tick_bytes_len += bytes.len() + 8 + 40;
        if messaging.tick_bytes_len > node.messaging_properties.max_tick_bytes_len {
            ReadServerBytesResult::ServerMaxTickByteLenOverflow
        } else {
            let _ = node
                .node_type
                .connected_server
                .receiving_bytes_sender
                .try_send(bytes);
            ReadServerBytesResult::ServerReceivedBytes
        }
    }
}

impl NodeType for ClientNode {
    type Skt = Vec<u8>;

    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>> {
        &self.state
    }
}

/// Connected client.
///
/// # Info
/// **See more information about the client creation and management in [`client`](crate::client) module.**
pub struct Client {
    internal: Arc<NodeInternal<ClientNode>>,
}

impl Client {
    /// Connect to a server via a [`UdpSocket`], creating a new Client instance.
    ///
    /// Additional sockets may be used depending on the authentication mode.
    pub fn connect(
        remote_addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        client_properties: Arc<ClientProperties>,
        authenticator_mode: AuthenticatorMode,
        #[cfg(any(feature = "rt_tokio", feature = "rt_async_executor"))]
        runtime: crate::internal::rt::Runtime,
    ) -> TaskHandle<Result<ConnectResult, ConnectError>> {
        #[cfg(any(feature = "rt_tokio", feature = "rt_async_executor"))]
        let task_runner = Arc::new(TaskRunner { runtime });

        #[cfg(not(any(feature = "rt_tokio", feature = "rt_async_executor")))]
        let task_runner = Arc::new(TaskRunner {});

        let task_runner_exit = Arc::clone(&task_runner);

        let bind_result_body = async move {
            if !packet_registry.check_essential() {
                return Err(ConnectError::MissingEssentialPackets);
            }

            let client_private_key = EphemeralSecret::random_from_rng(OsRng);
            let client_public_key = PublicKey::from(&client_private_key);
            let client_public_key_bytes = client_public_key.as_bytes();

            let mut public_key_sent = Vec::with_capacity(1 + client_public_key_bytes.len());
            public_key_sent.push(MessageChannel::PUBLIC_KEY_SEND);
            public_key_sent.extend_from_slice(client_public_key_bytes);

            let mut buf = [0u8; UDP_BUFFER_SIZE];

            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => Arc::new(socket),
                Err(e) => {
                    return Err(ConnectError::SocketConnectError(e));
                }
            };

            if let Err(e) = socket.connect(remote_addr).await {
                return Err(ConnectError::SocketConnectError(e));
            }

            let (len, auth_message, connected_authentication_mode) =
                connecting::connect_auth_mode_match_arm(
                    authenticator_mode,
                    &client_properties,
                    &socket,
                    &mut buf,
                    &public_key_sent,
                )
                .await?;

            let bytes = &buf[..len];

            match bytes[0] {
                MessageChannel::PUBLIC_KEY_SEND => {
                    if len != (MESSAGE_CHANNEL_SIZE + PUBLIC_KEY_SIZE) {
                        return Err(ConnectError::InvalidProtocolCommunication);
                    }
                    return connecting::connect_public_key_send_match_arm(
                        socket,
                        buf,
                        client_private_key,
                        auth_message,
                        packet_registry,
                        messaging_properties,
                        read_handler_properties,
                        client_properties,
                        task_runner,
                        remote_addr,
                        connected_authentication_mode,
                    )
                    .await;
                }
                _ => Err(ConnectError::InvalidProtocolCommunication),
            }
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

    /// Client Properties getter.
    pub fn client_properties(&self) -> &ClientProperties {
        &self.internal.node_type.client_properties
    }

    /// Client Properties getter.
    pub fn connected_server(&self) -> &ConnectedServer {
        &self.internal.node_type.connected_server
    }

    /// Authentication mode of the client and server.
    pub fn auth_mode(&self) -> &ConnectedAuthenticatorMode {
        &self.internal.node_type.authentication_mode
    }

    /// Client periodic tick start.
    ///
    /// This function call rate should be at least a little bit higher than server tick ratio.
    ///
    /// It handles:
    /// - Server sent packets
    /// - General client cyclic management
    ///
    /// # Errors
    /// If [`Client::try_tick_after_message`] call is pending.
    pub fn try_tick_start(&self) -> Result<ClientTickResult, ()> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        {
            let tick_state = node_type.tick_state.read().unwrap();
            if *tick_state != ClientTickState::TickStartPending {
                return Err(());
            }
        }

        if self.is_disconnected() {
            return Ok(ClientTickResult::Disconnected);
        }

        if let Ok(reason) = node_type.reason_to_disconnect_receiver.try_recv() {
            *node_type.disconnect_reason.write().unwrap() = Some(Some(reason));
            return Ok(ClientTickResult::Disconnected);
        }

        let now = Instant::now();

        let server = &node_type.connected_server;
        if let Some(mut messaging) = try_lock(&server.messaging) {
            *server.last_messaging_write.write().unwrap() = now;
            *server.average_latency.write().unwrap() = messaging.latency_monitor.average_value();

            let average_packet_loss_rtt = messaging.average_packet_loss_rtt;
            let mut messages_to_resend: Vec<Arc<Vec<u8>>> = Vec::new();

            for (sent_instant, pending_part_id_map) in messaging.pending_confirmation.values_mut() {
                if now - *sent_instant > internal.messaging_properties.timeout_interpretation {
                    *node_type.disconnect_reason.write().unwrap() = Some(Some(
                        ServerDisconnectReason::PendingMessageConfirmationTimeout,
                    ));
                    return Ok(ClientTickResult::Disconnected);
                }
                for sent_part in pending_part_id_map.values_mut() {
                    if now - sent_part.last_sent_time > average_packet_loss_rtt {
                        sent_part.last_sent_time = now;
                        messages_to_resend.push(Arc::clone(&sent_part.finished_bytes));
                    }
                }
            }

            for finished_bytes in messages_to_resend {
                server
                    .shared_socket_bytes_send_sender
                    .try_send(finished_bytes)
                    .unwrap();
            }

            if !messaging.received_messages.is_empty() {
                let message = messaging.received_messages.remove(0);
                {
                    let mut tick_state = node_type.tick_state.write().unwrap();
                    *tick_state = ClientTickState::TickAfterMessagePending;
                }

                messaging.tick_bytes_len = 0;

                #[cfg(feature = "store_unexpected")]
                let unexpected_errors = match node_type
                    .store_unexpected_errors
                    .error_list_receiver
                    .try_recv()
                {
                    Ok(list) => list,
                    Err(_) => Vec::new(),
                };

                #[cfg(feature = "store_unexpected")]
                node_type
                    .store_unexpected_errors
                    .create_list_signal_sender
                    .try_send(())
                    .unwrap();

                ClientNode::try_check_read_handler(internal);

                return Ok(ClientTickResult::ReceivedMessage(
                    ReceivedMessageClientTickResult {
                        message,
                        #[cfg(feature = "store_unexpected")]
                        unexpected_errors,
                    },
                ));
            } else if now - messaging.last_received_message_instant
                >= internal.messaging_properties.timeout_interpretation
            {
                *node_type.disconnect_reason.write().unwrap() =
                    Some(Some(ServerDisconnectReason::MessageReceiveTimeout));
                return Ok(ClientTickResult::Disconnected);
            } else {
                return Ok(ClientTickResult::PendingMessage);
            }
        } else if now - *server.last_messaging_write.read().unwrap()
            >= internal.messaging_properties.timeout_interpretation
        {
            *node_type.disconnect_reason.write().unwrap() =
                Some(Some(ServerDisconnectReason::WriteUnlockTimeout));
            return Ok(ClientTickResult::Disconnected);
        } else {
            return Ok(ClientTickResult::WriteLocked);
        }
    }

    /// Panic version of [`Client::try_tick_start`].
    ///
    /// Client periodic tick start.
    ///
    /// This function call rate should be at least a little bit higher than server tick ratio.
    ///
    /// It handles:
    /// - Server sent packets
    /// - General client cyclic management
    ///
    /// # Panics
    /// If [`Client::tick_after_message`] call is pending.
    #[cfg(not(feature = "no_panics"))]
    pub fn tick_start(&self) -> ClientTickResult {
        self.try_tick_start().expect("Invalid client tick state.")
    }

    /// Client tick after [`ClientTickResult::ReceivedMessage`] is returned form [`Client::try_tick_start`]
    ///
    /// It handles:
    /// - Unification of packages to be sent to server.
    ///
    /// # Errors
    /// If is not called after [`Client::try_tick_start`]
    pub fn try_tick_after_message(&self) -> Result<(), ()> {
        let internal = &self.internal;
        let node_type = &internal.node_type;
        {
            let mut tick_state = node_type.tick_state.write().unwrap();
            if *tick_state != ClientTickState::TickAfterMessagePending {
                return Err(());
            } else {
                *tick_state = ClientTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = internal
            .packet_registry
            .try_serialize(&ClientTickEndPacket)
            .unwrap();

        let connected_server = &node_type.connected_server;
        self.send_packet_serialized(tick_packet_serialized.clone());
        connected_server
            .packets_to_send_sender
            .try_send(None)
            .unwrap();

        Ok(())
    }

    /// Panic version of [`Client::try_tick_after_message`].
    ///
    /// Client tick after [`ClientTickResult::ReceivedMessage`] is returned form [`Client::tick_start`]
    ///
    /// It handles:
    /// - Unification of packages to be sent to server.
    ///
    /// # Panics
    /// If is not called after [`Client::tick_start`]
    #[cfg(not(feature = "no_panics"))]
    pub fn tick_after_message(&self) {
        self.try_tick_after_message()
            .expect("Invalid client tick state.")
    }

    /// Disconnect the client from the server gracefully if there is some message.
    ///
    /// # Examples
    /// ```no_run
    /// use std::time::Duration;
    /// use lyanne::{client::*, packets::{Packet, SerializedPacketList}, LimitedMessage};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// async fn example_usage(client: Client) {
    ///     let message = LimitedMessage::new(SerializedPacketList::single(
    ///         client.packet_registry().serialize(&MessagePacket {
    ///             message: "We finished here...".to_owned(),
    ///         }),
    ///     ));
    ///     let state = client
    ///         .disconnect(Some(GracefullyDisconnection {
    ///             message,
    ///             timeout: Duration::from_secs(3),
    ///         }))
    ///         .await;
    ///     println!("Client disconnected itself: {:?}", state);
    /// }
    /// ```
    pub fn disconnect(
        self,
        disconnection: Option<GracefullyDisconnection>,
    ) -> TaskHandle<ClientDisconnectState> {
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

            if self.is_disconnected() {
                return ClientDisconnectState::AlreadyDisconnected(self.take_disconnect_reason());
            }

            if let Some(disconnection) = disconnection {
                let socket = Arc::clone(&self.internal.node_type.socket);
                let timeout_interpretation = disconnection.timeout;
                let packet_loss_timeout = self
                    .internal
                    .node_type
                    .connected_server
                    .messaging
                    .lock()
                    .await
                    .average_packet_loss_rtt
                    .min(timeout_interpretation);

                let rejection_context = self
                    .internal
                    .node_type
                    .connected_server
                    .inner_auth
                    .rejection_of(Instant::now(), disconnection.message);

                let rejection_confirm_bytes = &vec![MessageChannel::REJECTION_CONFIRM];

                let disconnect_state = loop {
                    let now = Instant::now();
                    if now - rejection_context.rejection_instant > timeout_interpretation {
                        break ClientDisconnectState::ConfirmationTimeout;
                    }

                    if let Err(e) = socket.send(&rejection_context.finished_bytes).await {
                        break ClientDisconnectState::SendIoError(e);
                    }

                    let pre_read_next_bytes_result = {
                        if let Ok(result) = received_bytes_receiver.try_recv() {
                            Ok(result)
                        } else {
                            ClientNode::pre_read_next_bytes(&socket, packet_loss_timeout).await
                        }
                    };

                    match pre_read_next_bytes_result {
                        Ok(result) => {
                            if &result == rejection_confirm_bytes {
                                break ClientDisconnectState::Confirmed;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                        Err(e) => break ClientDisconnectState::ReceiveIoError(e),
                    }
                };

                drop(self);
                let _ = tasks_keeper.cancel(tasks_keeper_handle).await;

                disconnect_state
            } else {
                drop(self);
                let _ = tasks_keeper.cancel(tasks_keeper_handle).await;

                ClientDisconnectState::WithoutReason
            }
        })
    }

    /// Serializes, then store the packet to be sent to the server after the next received server tick.
    ///
    /// # Parameters
    ///
    /// * `packet` - packet to be serialized and sent.
    ///
    /// # Errors
    ///
    /// If the packet serialization fails, or if `P` was not registered in PacketRegistry.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use lyanne::{client::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(client: &Client) {
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     client.try_send_packet(&packet).unwrap();
    /// }
    /// ```
    pub fn try_send_packet<P: Packet>(&self, packet: &P) -> Result<(), io::Error> {
        let internal = &self.internal;
        let serialized = internal.packet_registry.try_serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }

    /// Panic version of [`Client::try_send_packet`].
    ///
    /// Serializes, then store the packet to be sent to the server after the next received server tick.
    ///
    /// # Parameters
    ///
    /// * `packet` - packet to be serialized and sent.
    ///
    /// # Panics
    ///
    /// If the packet serialization fails, or if `P` was not registered in PacketRegistry.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use lyanne::{client::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(client: &Client) {
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     client.send_packet(&packet);
    /// }
    /// ```
    #[cfg(not(feature = "no_panics"))]
    pub fn send_packet<P: Packet>(&self, packet: &P) {
        self.try_send_packet(packet)
            .expect("Failed to send packet.");
    }

    /// Store the packet to be sent to the client after the next server tick.
    ///
    /// # Parameters
    ///
    /// * `client` - `ConnectedClient` to which the packet will be sent.
    /// * `packet` - packet to be sent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use lyanne::{client::*, packets::Packet};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Packet, Deserialize, Serialize, Debug)]
    /// struct MessagePacket {
    ///     message: String,
    /// }
    ///
    /// fn example_usage(client: &Client) {
    ///     let packet = MessagePacket {
    ///         message: "Hey ya!".to_owned(),
    ///     };
    ///     let packet_serialized = client.packet_registry().serialize(&packet);
    ///     client.send_packet_serialized(packet_serialized);
    /// }
    /// ```
    pub fn send_packet_serialized(&self, packet_serialized: SerializedPacket) {
        let internal = &self.internal;
        internal
            .node_type
            .connected_server
            .packets_to_send_sender
            .try_send(Some(packet_serialized))
            .unwrap();
    }

    /// # Returns
    /// If the [`Client::try_tick_start`] returned [`ClientTickResult::Disconnected`] some time.
    pub fn is_disconnected(&self) -> bool {
        let internal = &self.internal;
        let disconnect_reason = internal.node_type.disconnect_reason.read().unwrap();
        disconnect_reason.is_some()
    }

    /// # Returns
    /// - `None` if the client was not disconnected.
    /// - `None` if the client was disconnected, but the reason was taken by another call of this function.
    /// - `Some` if the client was disconnected, and take the reason.
    pub fn take_disconnect_reason(&self) -> Option<ServerDisconnectReason> {
        let internal = &self.internal;
        let mut disconnect_reason = internal.node_type.disconnect_reason.write().unwrap();
        if let Some(ref mut is_disconnected) = *disconnect_reason {
            if let Some(reason_was_not_taken) = is_disconnected.take() {
                // Disconnected, and the reason will be taken.
                Some(reason_was_not_taken)
            } else {
                // Disconnected, but the reason was taken.
                None
            }
        } else {
            // Was not disconnected.
            None
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        NodeInternal::on_holder_drop(&self.internal);
    }
}
