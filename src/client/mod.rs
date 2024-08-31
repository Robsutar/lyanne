use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    messages::{DeserializedMessage, MessageId, MessagePartId, MessagePartMap},
    packets::{
        ClientTickEndPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList,
    },
    rt::{cancel, spawn, timeout, try_lock, Mutex, TaskHandle, UdpSocket},
    utils::{DurationMonitor, RttCalculator},
};

use crate::{
    JustifiedRejectionContext, MessageChannel, MessagingProperties, ReadHandlerProperties,
    SentMessagePart, MESSAGE_CHANNEL_SIZE,
};

pub use auth::*;
use init::*;

mod auth;
mod init;

/// Possible results when receiving bytes by the server
#[derive(Debug)]
pub enum ReadServerBytesResult {
    /// Disconnect confirmation from the server is done.
    DoneDisconnectConfirm,
    /// Disconnect confirmation from the server is pending.
    PendingDisconnectConfirm,
    /// The byte length for authentication is insufficient.
    AuthInsufficientBytesLen,
    /// The server has exceeded the maximum tick byte length.
    ServerMaxTickByteLenOverflow,
    /// Bytes were successfully received from the server.
    ServerReceivedBytes,
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

/// Result when calling [`Client::tick_start`]
#[derive(Debug)]
pub enum ClientTickResult {
    ReceivedMessage(DeserializedMessage),
    PendingMessage,
    /// The client was disconnected from the server.
    ///
    /// After this is returned by the tick, is possible to use [`Client::get_disconnect_reason`]
    Disconnected,
    WriteLocked,
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
    /// Error sending/receiving the bytes of the server.
    Error(io::Error),
}

/// Result when calling [`Client::disconnect`].
pub struct ClientDisconnectResult {
    /// The state of the disconnection.
    pub state: ClientDisconnectState,
}

/// Messaging fields of [`ConnectedServer`]
///
/// Intended to be used with [`Mutex`].
pub struct ConnectedServerMessaging {
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

/// Properties of the server that is connected to the client.
///
/// Intended to be used inside [`ServerInternal`] with [`Arc`].
pub struct ConnectedServer {
    /// Sender for receiving bytes.
    receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    /// Sender for packets to be sent.
    packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,
    /// Sender for message part confirmations.
    message_part_confirmation_sender: async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

    /// The socket address of the connected server.
    addr: SocketAddr,
    /// The socket address of the connected server.
    auth_mode: ConnectedAuthenticatorMode,

    /// Messaging-related properties wrapped in an `Arc` and `RwLock`.
    messaging: Mutex<ConnectedServerMessaging>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,
    /// The byte size of [`ConnectedClientMessaging::incoming_messages`]
    incoming_messages_total_size: RwLock<usize>,
}

impl ConnectedServer {
    /// # Returns
    /// The remove server address.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn auth_mode(&self) -> &ConnectedAuthenticatorMode {
        &self.auth_mode
    }

    /// # Returns
    /// The average time of messaging response of the server after a client message + server tick delay
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    /// # Returns
    /// The total size of the stored incoming messages, that were not completed wet, or not read yet.
    pub fn incoming_messages_total_size(&self) -> usize {
        *self.incoming_messages_total_size.read().unwrap()
    }
}

/// Properties of the client.
///
/// Intended to be used inside [`Client`].
struct ClientInternal {
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: async_channel::Sender<TaskHandle<()>>,
    /// Sender for addresses to be disconnected.
    reason_to_disconnect_sender: async_channel::Sender<ServerDisconnectReason>,
    /// Receiver for addresses to be disconnected.
    reason_to_disconnect_receiver: async_channel::Receiver<ServerDisconnectReason>,

    /// Task handle of the receiver.
    tasks_keeper_handle: Mutex<Option<TaskHandle<()>>>,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    #[cfg(feature = "rt_tokio")]
    /// The runtime for asynchronous operations.
    runtime: crate::rt::Runtime,
    /// Actual state of client periodic tick flow.
    tick_state: RwLock<ClientTickState>,

    /// The registry for packets.
    packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    read_handler_properties: Arc<ReadHandlerProperties>,
    /// Properties for the internal client management.
    client_properties: Arc<ClientProperties>,

    /// Connected server.
    connected_server: Arc<ConnectedServer>,

    /// Reason that caused the connection finish.
    ///
    /// If equals to [`Option::None`], the client was disconnected.
    /// If inner [`Option::Some`] equals to [`Option::None`], the disconnect reason was taken.
    disconnect_reason: RwLock<Option<Option<ServerDisconnectReason>>>,
}

impl ClientInternal {
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
            timeout(read_timeout, async move {
                let mut buf = [0u8; 1024];
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

    async fn read_next_bytes(self: &Arc<Self>, bytes: Vec<u8>) -> ReadServerBytesResult {
        let mut messaging = self.connected_server.messaging.lock().await;
        // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
        messaging.tick_bytes_len += bytes.len() + 8 + 20;
        if messaging.tick_bytes_len > self.messaging_properties.max_client_tick_bytes_len {
            ReadServerBytesResult::ServerMaxTickByteLenOverflow
        } else {
            let _ = self.connected_server.receiving_bytes_sender.try_send(bytes);
            ReadServerBytesResult::ServerReceivedBytes
        }
    }
}

/// Connected client.
pub struct Client {
    internal: Arc<ClientInternal>,
}

impl Client {
    /// Connect to a server via a [`UdpSocket`], creating a new Client instance.
    pub fn connect(
        remote_addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        client_properties: Arc<ClientProperties>,
        authenticator_mode: AuthenticatorMode,
        #[cfg(feature = "rt_tokio")] runtime: crate::rt::Runtime,
    ) -> TaskHandle<Result<ConnectResult, ConnectError>> {
        #[cfg(feature = "rt_tokio")]
        let runtime_exit = runtime.clone();

        let bind_result_body = async move {
            let client_private_key = EphemeralSecret::random_from_rng(OsRng);
            let client_public_key = PublicKey::from(&client_private_key);
            let client_public_key_bytes = client_public_key.as_bytes();

            let mut public_key_sent = Vec::with_capacity(1 + client_public_key_bytes.len());
            public_key_sent.push(MessageChannel::PUBLIC_KEY_SEND);
            public_key_sent.extend_from_slice(client_public_key_bytes);

            let mut buf = [0u8; 1024];

            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            socket.connect(remote_addr).await?;

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
                MessageChannel::IGNORED_REASON => {
                    // 4 for the minimal SerializedPacket
                    if bytes.len() < MESSAGE_CHANNEL_SIZE + 4 {
                        return Err(ConnectError::InvalidProtocolCommunication);
                    } else if let Ok(message) =
                        DeserializedMessage::deserialize_single_list(&bytes[1..], &packet_registry)
                    {
                        return Err(ConnectError::Ignored(message));
                    } else {
                        return Err(ConnectError::InvalidProtocolCommunication);
                    }
                }
                MessageChannel::PUBLIC_KEY_SEND => {
                    if len != 33 {
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
                        #[cfg(feature = "rt_tokio")]
                        runtime,
                        remote_addr,
                        connected_authentication_mode,
                    )
                    .await;
                }
                _ => Err(ConnectError::InvalidProtocolCommunication),
            }
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

    /// Client Properties getter.
    pub fn client_properties(&self) -> &ClientProperties {
        &self.internal.client_properties
    }

    /// Client Properties getter.
    pub fn connected_server(&self) -> &ConnectedServer {
        &self.internal.connected_server
    }

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
    pub fn tick_start(&self) -> ClientTickResult {
        let internal = &self.internal;
        {
            let tick_state = internal.tick_state.read().unwrap();
            if *tick_state != ClientTickState::TickStartPending {
                panic!(
                    "Invalid client tick state, next pending is {:?}",
                    tick_state
                );
            }
        }

        if self.is_disconnected() {
            return ClientTickResult::Disconnected;
        }

        if let Ok(reason) = internal.reason_to_disconnect_receiver.try_recv() {
            *internal.disconnect_reason.write().unwrap() = Some(Some(reason));
            return ClientTickResult::Disconnected;
        }

        let now = Instant::now();

        let server = &internal.connected_server;
        if let Some(mut messaging) = try_lock(&server.messaging) {
            *server.last_messaging_write.write().unwrap() = now;
            *server.average_latency.write().unwrap() = messaging.latency_monitor.average_value();

            let average_packet_loss_rtt = messaging.average_packet_loss_rtt;
            let mut messages_to_resend: Vec<Arc<Vec<u8>>> = Vec::new();

            for (sent_instant, pending_part_id_map) in messaging.pending_confirmation.values_mut() {
                if now - *sent_instant > internal.messaging_properties.timeout_interpretation {
                    *internal.disconnect_reason.write().unwrap() = Some(Some(
                        ServerDisconnectReason::PendingMessageConfirmationTimeout,
                    ));
                    return ClientTickResult::Disconnected;
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
                    let mut tick_state = internal.tick_state.write().unwrap();
                    *tick_state = ClientTickState::TickAfterMessagePending;
                }

                messaging.tick_bytes_len = 0;

                internal.try_check_read_handler();

                return ClientTickResult::ReceivedMessage(message);
            } else if now - messaging.last_received_message_instant
                >= internal.messaging_properties.timeout_interpretation
            {
                *internal.disconnect_reason.write().unwrap() =
                    Some(Some(ServerDisconnectReason::MessageReceiveTimeout));
                return ClientTickResult::Disconnected;
            } else {
                return ClientTickResult::PendingMessage;
            }
        } else if now - *server.last_messaging_write.read().unwrap()
            >= internal.messaging_properties.timeout_interpretation
        {
            *internal.disconnect_reason.write().unwrap() =
                Some(Some(ServerDisconnectReason::WriteUnlockTimeout));
            return ClientTickResult::Disconnected;
        } else {
            return ClientTickResult::WriteLocked;
        }
    }

    /// Client tick after [`ClientTickResult::ReceivedMessage`] is returned form [`Client::tick`]
    ///
    /// It handles:
    /// - Unification of packages to be sent to server.
    ///
    /// # Panics
    /// If is not called after [`Client::tick_start`]
    pub fn tick_after_message(&self) {
        let internal = &self.internal;
        {
            let mut tick_state = internal.tick_state.write().unwrap();
            if *tick_state != ClientTickState::TickAfterMessagePending {
                panic!(
                    "Invalid server tick state, next pending is {:?}",
                    tick_state
                );
            } else {
                *tick_state = ClientTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = internal.packet_registry.serialize(&ClientTickEndPacket);

        let connected_server = &internal.connected_server;
        self.send_packet_serialized(tick_packet_serialized.clone());
        connected_server
            .packets_to_send_sender
            .try_send(None)
            .unwrap();
    }

    /// Disconnect the client from the server gracefully if there is some message.
    ///
    /// # Examples
    /// ```no_run
    /// let client: Client = ...;
    ///
    /// let message = Some(SerializedPacketList::create(vec![client
    ///     .packet_registry()
    ///     .serialize(&BarPacket {
    ///         message: "We finished here...".to_owned(),
    ///     })]));
    ///
    /// let result = client.disconnect(message).await.unwrap();
    /// println!("Client disconnected itself: {:?}", result.state);
    /// ```
    pub fn disconnect(
        self,
        message: Option<SerializedPacketList>,
    ) -> TaskHandle<ClientDisconnectResult> {
        spawn(
            #[cfg(feature = "rt_tokio")]
            &self.internal.runtime.clone(),
            async move {
                let sent_time = Instant::now();

                let tasks_keeper_handle = self
                    .internal
                    .tasks_keeper_handle
                    .lock()
                    .await
                    .take()
                    .unwrap();
                cancel(tasks_keeper_handle).await;

                let socket = Arc::clone(&self.internal.socket);
                let read_timeout = self
                    .internal
                    .client_properties
                    .auth_packet_loss_interpretation;
                let timeout_interpretation =
                    self.internal.messaging_properties.timeout_interpretation;

                drop(self);

                if let Some(list) = message {
                    let context =
                        JustifiedRejectionContext::from_serialized_list(Instant::now(), list);

                    let rejection_confirm_bytes = &vec![MessageChannel::REJECTION_CONFIRM];

                    loop {
                        let now = Instant::now();
                        if let Err(e) = socket.send(&context.finished_bytes).await {
                            return ClientDisconnectResult {
                                state: ClientDisconnectState::Error(e),
                            };
                        }

                        let pre_read_next_bytes_result =
                            ClientInternal::pre_read_next_bytes(&socket, read_timeout).await;

                        match pre_read_next_bytes_result {
                            Ok(result) => {
                                if &result == rejection_confirm_bytes {
                                    return ClientDisconnectResult {
                                        state: ClientDisconnectState::Confirmed,
                                    };
                                }
                            }
                            Err(_) => {
                                if now - sent_time > timeout_interpretation {
                                    return ClientDisconnectResult {
                                        state: ClientDisconnectState::ConfirmationTimeout,
                                    };
                                }
                            }
                        }
                    }
                } else {
                    ClientDisconnectResult {
                        state: ClientDisconnectState::WithoutReason,
                    }
                }
            },
        )
    }

    /// Serializes, then store the packet to be sent to the server after the next received server tick.
    ///
    /// # Parameters
    ///
    /// * `packet` - packet to be serialized and sent.
    ///
    /// # Panics
    ///
    /// If the packet serialization fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let client: &Client = ...;
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// client.send_packet(&packet);
    /// ```
    pub fn send_packet<P: Packet>(&self, packet: &P) {
        let internal = &self.internal;
        let serialized = internal.packet_registry.serialize(packet);
        self.send_packet_serialized(serialized);
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
    /// let client: &Client = ...;
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// let packet_serialized = client.packet_registry().serialize(&packet);
    /// client.send_packet_serialized(&packet_serialized);
    /// ```
    pub fn send_packet_serialized(&self, packet_serialized: SerializedPacket) {
        let internal = &self.internal;
        internal
            .connected_server
            .packets_to_send_sender
            .try_send(Some(packet_serialized))
            .unwrap();
    }

    /// # Returns
    /// If the [`Client::tick_start`] returned [`ClientTickResult::Disconnected`] some time.
    pub fn is_disconnected(&self) -> bool {
        let internal = &self.internal;
        let disconnect_reason = internal.disconnect_reason.read().unwrap();
        disconnect_reason.is_some()
    }

    /// # Returns
    /// - `None` if the client was not disconnected.
    /// - `None` if the client was disconnected, but the reason was taken by another call of this function.
    /// - `Some` if the client was disconnected, and take the reason.
    pub fn take_disconnect_reason(&self) -> Option<ServerDisconnectReason> {
        let internal = &self.internal;
        let mut disconnect_reason = internal.disconnect_reason.write().unwrap();
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

    /// TODO:
    pub fn disconnect_detached(self) {
        todo!();
    }
}