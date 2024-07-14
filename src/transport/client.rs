use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use tokio::{net::UdpSocket, runtime::Runtime, task::JoinHandle, time::timeout};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    messages::{
        DeserializedMessage, MessageId, MessagePart, MessagePartId, MessagePartMap, MessagePartMapTryInsertResult, MessagePartMapTryReadResult, MINIMAL_PART_BYTES_SIZE
    },
    packets::{
        ClientTickEndPacket, DeserializedPacket, Packet, PacketRegistry, SerializedPacket,
        SerializedPacketList,
    },
    utils::{DurationMonitor, RttCalculator},
};

use super::{
    JustifiedRejectionContext, MessageChannel, MessagingProperties, ReadHandlerProperties,
    SentMessagePart, MESSAGE_CHANNEL_SIZE,
};

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
    ByteSendError,
    /// Server was manually disconnected.
    ManualDisconnect,
    /// Server disconnected itself.
    DisconnectRequest,
}

/// Result when calling [`Client::connect`]
pub struct ConnectResult {
    pub client: Arc<Client>,
    pub message: DeserializedMessage,
}

/// Client tick flow state.
#[derive(Debug, PartialEq, Eq)]
enum ClientTickState {
    /// Next call should be [`Client::tick_start`].
    TickStartPending,
    /// Next call should be [`Client::tick_end`].
    TickAfterMessagePending,
}

#[derive(Debug)]
pub enum ConnectError {
    Timeout,
    InvalidProtocolCommunication,
    Ignored(Vec<DeserializedPacket>),
    Rejected(Vec<DeserializedPacket>),
    IoError(io::Error),
    Disconnected(ServerDisconnectReason),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::Timeout => write!(f, "Server took a long time to respond."),
            ConnectError::InvalidProtocolCommunication => {
                write!(f, "Server did not communicate correctly.")
            }
            ConnectError::Ignored(message) => write!(
                f,
                "Client addr is ignored by the server, reason size: {}",
                message.len()
            ),
            ConnectError::Rejected(message) => write!(
                f,
                "Connection was refused by the server, reason size: {}",
                message.len()
            ),
            ConnectError::IoError(ref err) => write!(f, "IO error: {}", err),
            ConnectError::Disconnected(reason) => write!(f, "Disconnected: {:?}", reason),
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

/// Messaging fields of [`ConnectedServer`]
///
/// Intended to be used with [`Arc`] and [`RwLock`]
pub struct ConnectedServerMessaging {
    /// The cipher used for encrypting and decrypting messages.
    cipher: ChaCha20Poly1305,

    /// Map of message parts pending confirmation.
    /// The tuple is the sent instant, and the map of the message parts of the message.
    pending_confirmation: BTreeMap<MessageId, (Instant, BTreeMap<MessagePartId, SentMessagePart>)>,

    /// Map of incoming message parts.
    incoming_message: MessagePartMap,
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

    /// Sender for message part confirmations.
    message_part_confirmation_sender: crossbeam_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    shared_socket_bytes_send_sender: crossbeam_channel::Sender<Arc<Vec<u8>>>,
}

/// Properties of a server that is connected to the server.
///
/// Intended to be used inside `ServerAsync`.
pub struct ConnectedServer {
    /// The socket address of the connected server.
    addr: SocketAddr,

    /// Messaging-related properties wrapped in an `Arc` and `RwLock`.
    messaging: Arc<RwLock<ConnectedServerMessaging>>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,

    /// Sender for receiving bytes.
    receiving_bytes_sender: crossbeam_channel::Sender<Vec<u8>>,

    /// Sender for packets to be sent.
    packets_to_send_sender: crossbeam_channel::Sender<Option<SerializedPacket>>,
}

impl ConnectedServer {
    /// # Returns
    /// The average time of messaging response of the server after a client message + server tick delay
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    /// # Returns
    /// The remove server address.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    async fn create_receiving_bytes_handler(
        client: Weak<Client>,
        messaging: Arc<RwLock<ConnectedServerMessaging>>,
        receiving_bytes_receiver: crossbeam_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv() {
            if let Some(client) = client.upgrade() {
                let mut messaging = messaging.write().unwrap();
                match bytes[0] {
                    MessageChannel::MESSAGE_PART_CONFIRM => {
                        if bytes.len() == 3 {
                            let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                            if let Some((sent_instant, _)) =
                                messaging.pending_confirmation.remove(&message_id)
                            {
                                let delay = Instant::now() - sent_instant;
                                messaging.latency_monitor.push(delay);
                                // TODO: adjust that, see `2ccbdfd06a2f256d1e5f872cb7ed3d3ba523a402`
                                messaging.average_packet_loss_rtt = Duration::from_millis(250);
                            }
                        } else if bytes.len() == 5 {
                            let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                            let part_id = MessagePartId::from_be_bytes([bytes[3], bytes[4]]);
                            if let Some((sent_instant, map)) =
                                messaging.pending_confirmation.get_mut(&message_id)
                            {
                                let sent_instant = *sent_instant;
                                if let Some(_) = map.remove(&part_id) {
                                    if map.is_empty() {
                                        messaging.pending_confirmation.remove(&message_id).unwrap();
                                    }

                                    let delay = Instant::now() - sent_instant;
                                    messaging.latency_monitor.push(delay);
                                    // TODO: adjust that, see `2ccbdfd06a2f256d1e5f872cb7ed3d3ba523a402`
                                    messaging.average_packet_loss_rtt = Duration::from_millis(250);
                                }
                            }
                        } else {
                            let _ = client
                                .reason_to_disconnect_sender
                                .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                            break 'l1;
                        }
                    }
                    MessageChannel::MESSAGE_PART_SEND => {
                        // 12 for nonce
                        if bytes.len() < MESSAGE_CHANNEL_SIZE + MINIMAL_PART_BYTES_SIZE + 12 {
                            let _ = client
                                .reason_to_disconnect_sender
                                .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                            break 'l1;
                        }

                        let nonce = Nonce::from_slice(&bytes[1..13]);
                        let cipher_text = &bytes[13..];

                        if let Ok(decrypted_message) = messaging.cipher.decrypt(nonce, cipher_text)
                        {
                            if let Ok(part) = MessagePart::deserialize(decrypted_message) {
                                let mut send_fully_message_confirmation = false;
                                let message_id = part.message_id();
                                let part_id = part.id();

                                match messaging.incoming_message.try_insert(part) {
                                    MessagePartMapTryInsertResult::PastMessageId => {
                                        let _ = messaging
                                        .message_part_confirmation_sender
                                        .send((message_id, None));
                                    },
                                    MessagePartMapTryInsertResult::Stored => {
                                        'l2: loop {
                                            match messaging.incoming_message.try_read(&client.packet_registry){
                                                MessagePartMapTryReadResult::PendingParts => break 'l2,
                                                MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                                    let _ = client.reason_to_disconnect_sender.send((
                                                        ServerDisconnectReason::InvalidProtocolCommunication,
                                                        None,
                                                    ));
                                                    break 'l1;
                                                },
                                                MessagePartMapTryReadResult::SuccessfullyCreated(message) => {
                                                    send_fully_message_confirmation = true;
        
                                                    messaging.received_messages.push(message);
                                                    messaging.last_received_message_instant = Instant::now();
                                                },
                                            }
                                        }
        
                                        if send_fully_message_confirmation {
                                            let _ = messaging
                                                .message_part_confirmation_sender
                                                .send((message_id, None));
                                        } else {
                                            let _ = messaging
                                                .message_part_confirmation_sender
                                                .send((message_id, Some(part_id)));
                                        }
                                    },
                                }
                            } else {
                                let _ = client.reason_to_disconnect_sender.send((
                                    ServerDisconnectReason::InvalidProtocolCommunication,
                                    None,
                                ));
                                break 'l1;
                            }
                        } else {
                            let _ = client
                                .reason_to_disconnect_sender
                                .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                            break 'l1;
                        }
                    }
                    MessageChannel::DISCONNECT_REQUEST => {
                        let _ = client
                            .reason_to_disconnect_sender
                            .send((ServerDisconnectReason::DisconnectRequest, None));
                        break 'l1;
                    }
                    MessageChannel::AUTH_MESSAGE => {
                        // Client probably multiple authentication packets before being authenticated
                    }
                    _ => {
                        let _ = client
                            .reason_to_disconnect_sender
                            .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                        break 'l1;
                    }
                }
            }
        }
    }

    async fn create_packets_to_send_handler(
        client: Weak<Client>,
        messaging: Weak<RwLock<ConnectedServerMessaging>>,
        packets_to_send_receiver: crossbeam_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        while let Ok(serialized_packet) = packets_to_send_receiver.recv() {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(server) = client.upgrade() {
                    if let Some(messaging) = messaging.upgrade() {
                        let mut messaging = messaging.write().unwrap();
                        let packets_to_send = std::mem::replace(&mut packets_to_send, Vec::new());

                        let bytes = SerializedPacketList::create(packets_to_send).bytes;
                        let message_parts = MessagePart::create_list(
                            &server.messaging_properties,
                            next_message_id,
                            bytes,
                        )
                        .unwrap();

                        let sent_instant = Instant::now();

                        for part in message_parts {
                            let part_id = part.id();

                            let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                            let sent_part =
                                SentMessagePart::new(sent_instant, &part, &messaging.cipher, nonce);

                            let finished_bytes = Arc::clone(&sent_part.finished_bytes);

                            let (_, pending_part_id_map) = messaging
                                .pending_confirmation
                                .entry(part.message_id())
                                .or_insert_with(|| (sent_instant, BTreeMap::new()));
                            pending_part_id_map.insert(part_id, sent_part);

                            let _ = messaging
                                .shared_socket_bytes_send_sender
                                .send(finished_bytes);
                        }

                        next_message_id = next_message_id.wrapping_add(1);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    async fn create_message_part_confirmation_handler(
        client: Weak<Client>,
        message_part_confirmation_receiver: crossbeam_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv() {
            if let Some(client) = client.upgrade() {
                let message_id_bytes = message_id.to_be_bytes();

                let bytes = {
                    if let Some(part_id) = part_id {
                        let part_id_bytes = part_id.to_be_bytes();
                        vec![
                            MessageChannel::MESSAGE_PART_CONFIRM,
                            message_id_bytes[0],
                            message_id_bytes[1],
                            part_id_bytes[0],
                            part_id_bytes[1],
                        ]
                    } else {
                        vec![
                            MessageChannel::MESSAGE_PART_CONFIRM,
                            message_id_bytes[0],
                            message_id_bytes[1],
                        ]
                    }
                };
                if client.socket.send(&bytes).await.is_err() {
                    let _ = client
                        .reason_to_disconnect_sender
                        .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                    break;
                }
            }
        }
    }

    async fn create_shared_socket_bytes_send_handler(
        client: Weak<Client>,
        shared_socket_bytes_send_receiver: crossbeam_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        while let Ok(bytes) = shared_socket_bytes_send_receiver.recv() {
            if let Some(client) = client.upgrade() {
                if client.socket.send(&bytes).await.is_err() {
                    let _ = client
                        .reason_to_disconnect_sender
                        .send((ServerDisconnectReason::InvalidProtocolCommunication, None));
                    break;
                }
            }
        }
    }
}

/// Properties of the client.
///
/// Intended to be used with `Arc`.
pub struct Client {
    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    /// The runtime for asynchronous operations.
    runtime: Arc<Runtime>,
    /// Task handle of the receiver.
    tasks_keeper_handle: JoinHandle<()>,
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: crossbeam_channel::Sender<JoinHandle<()>>,
    /// Actual state of client periodic tick flow.
    tick_state: RwLock<ClientTickState>,

    /// The registry for packets.
    pub packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    pub messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    pub read_handler_properties: Arc<ReadHandlerProperties>,

    /// Connected server.
    connected_server: ConnectedServer,

    /// Sender for addresses to be disconnected.
    reason_to_disconnect_sender:
        crossbeam_channel::Sender<(ServerDisconnectReason, Option<JustifiedRejectionContext>)>,
    /// Receiver for addresses to be disconnected.
    reason_to_disconnect_receiver:
        crossbeam_channel::Receiver<(ServerDisconnectReason, Option<JustifiedRejectionContext>)>,

    /// Reason that caused the connection finish.
    ///
    /// If equals to [`Option::None`], the client was disconnected.
    /// If inner [`Option::Some`] equals to [`Option::None`], the disconnect reason was taken.
    disconnect_reason: RwLock<Option<Option<ServerDisconnectReason>>>,
}

impl Client {
    /// Connect to a server via a [`UdpSocket`], creating a new Client instance.
    pub async fn connect(
        remote_addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        runtime: Arc<Runtime>,
        message: SerializedPacketList,
    ) -> Result<ConnectResult, ConnectError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(remote_addr).await?;

        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);
        let client_public_key_bytes = client_public_key.as_bytes();

        let sent_time = Instant::now();

        let mut public_key_sent = Vec::with_capacity(1 + client_public_key_bytes.len());
        public_key_sent.push(MessageChannel::PUBLIC_KEY_SEND);
        public_key_sent.extend_from_slice(client_public_key_bytes);

        let mut buf = [0u8; 1024];
        loop {
            let now = Instant::now();
            if now - sent_time > messaging_properties.timeout_interpretation {
                return Err(ConnectError::Timeout);
            }

            socket.send(&public_key_sent).await?;
            match timeout(
                Duration::from_secs(3), // TODO: add value
                socket.recv(&mut buf),
            )
            .await
            {
                Ok(len) => {
                    let len = len?;
                    let bytes = &buf[..len];
                    if bytes.len() < MESSAGE_CHANNEL_SIZE {
                        return Err(ConnectError::InvalidProtocolCommunication);
                    }

                    match bytes[0] {
                        MessageChannel::REJECTION_JUSTIFICATION => {
                            socket
                                .send(&vec![MessageChannel::REJECTION_CONFIRM])
                                .await?;
                        }
                        MessageChannel::IGNORED_REASON => {
                            // 4 for the minimal SerializedPacket
                            if bytes.len() < MESSAGE_CHANNEL_SIZE + 4 {
                                return Err(ConnectError::InvalidProtocolCommunication);
                            } else if let Ok(message) =
                                DeserializedPacket::deserialize_list(&bytes[1..], &packet_registry)
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
                            return Client::connect_public_key_send_match_arm(
                                socket,
                                buf,
                                client_private_key,
                                message,
                                packet_registry,
                                messaging_properties,
                                read_handler_properties,
                                runtime,
                                remote_addr,
                                sent_time,
                            )
                            .await;
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }
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
    pub fn tick_start(self: &Arc<Self>) -> ClientTickResult {
        {
            let tick_state = self.tick_state.read().unwrap();
            if *tick_state != ClientTickState::TickStartPending {
                panic!(
                    "Invalid client tick state, next pending is {:?}",
                    tick_state
                );
            }
        }

        if Client::is_disconnected(&self) {
            return ClientTickResult::Disconnected;
        }

        if let Ok((reason, context)) = self.reason_to_disconnect_receiver.try_recv() {
            //TODO: use context
            *self.disconnect_reason.write().unwrap() = Some(Some(reason));
            return ClientTickResult::Disconnected;
        }

        let now = Instant::now();

        let connected_server = &self.connected_server;
        if let Ok(mut messaging) = connected_server.messaging.try_write() {
            *connected_server.last_messaging_write.write().unwrap() = now;
            *connected_server.average_latency.write().unwrap() =
                messaging.latency_monitor.average_value();

            let average_packet_loss_rtt = messaging.average_packet_loss_rtt;
            let mut messages_to_resend: Vec<Arc<Vec<u8>>> = Vec::new();

            for (sent_instant, pending_part_id_map) in messaging.pending_confirmation.values_mut() {
                if now - *sent_instant > self.messaging_properties.timeout_interpretation {
                    *self.disconnect_reason.write().unwrap() = Some(Some(
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
                messaging
                    .shared_socket_bytes_send_sender
                    .send(finished_bytes)
                    .unwrap();
            }

            if !messaging.received_messages.is_empty() {
                let message = messaging.received_messages.remove(0);
                {
                    let mut tick_state = self.tick_state.write().unwrap();
                    *tick_state = ClientTickState::TickAfterMessagePending;
                }

                messaging.tick_bytes_len = 0;

                self.try_check_read_handler();

                return ClientTickResult::ReceivedMessage(message);
            } else if now - messaging.last_received_message_instant
                >= self.messaging_properties.timeout_interpretation
            {
                println!(
                    "{:?}, {:?}",
                    messaging.incoming_message.next_message_id,
                    messaging.incoming_message.maps.keys(),
                );
                *self.disconnect_reason.write().unwrap() =
                    Some(Some(ServerDisconnectReason::MessageReceiveTimeout));
                return ClientTickResult::Disconnected;
            } else {
                return ClientTickResult::PendingMessage;
            }
        } else if now - *connected_server.last_messaging_write.read().unwrap()
            >= self.messaging_properties.timeout_interpretation
        {
            *self.disconnect_reason.write().unwrap() =
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
    pub fn tick_after_message(self: &Arc<Self>) {
        {
            let mut tick_state = self.tick_state.write().unwrap();
            if *tick_state != ClientTickState::TickAfterMessagePending {
                panic!(
                    "Invalid server tick state, next pending is {:?}",
                    tick_state
                );
            } else {
                *tick_state = ClientTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = self
            .packet_registry
            .serialize(&ClientTickEndPacket)
            .unwrap();

        let connected_server = &self.connected_server;
        self.send_packet_serialized(tick_packet_serialized.clone());
        connected_server.packets_to_send_sender.send(None).unwrap();
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
    /// let client: Arc<Client> = ...;
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// client.send_packet(&packet);
    /// ```
    pub fn send_packet<P: Packet>(&self, packet: &P) {
        let serialized = self
            .packet_registry
            .serialize(packet)
            .expect("Failed to serialize packet.");
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
    /// let client: Arc<Client> = ...;
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// let packet_serialized = client.packet_registry.serialize(&packet).expect("Failed to serialize packet.");
    /// client.send_packet_serialized(&packet_serialized);
    /// ```
    pub fn send_packet_serialized(&self, packet_serialized: SerializedPacket) {
        self.connected_server
            .packets_to_send_sender
            .send(Some(packet_serialized))
            .unwrap();
    }

    /// # Returns
    /// If the [`Client::tick_start`] returned [`ClientTickResult::Disconnected`] some time.
    pub fn is_disconnected(&self) -> bool {
        let disconnect_reason = self.disconnect_reason.read().unwrap();
        disconnect_reason.is_some()
    }

    /// # Returns
    /// - `None` if the client was not disconnected.
    /// - `None` if the client was disconnected, but the reason was taken by another call of this function.
    /// - `Some` if the client was disconnected, and take the reason.
    pub fn take_disconnect_reason(&self) -> Option<ServerDisconnectReason> {
        let mut disconnect_reason = self.disconnect_reason.write().unwrap();
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

    fn create_async_task<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let _ = self
            .tasks_keeper_sender
            .send(Arc::clone(&self.runtime).spawn(future));
    }

    fn create_async_tasks_keeper(
        runtime: Arc<Runtime>,
        tasks_keeper_receiver: crossbeam_channel::Receiver<tokio::task::JoinHandle<()>>,
    ) -> JoinHandle<()> {
        runtime.spawn(async move {
            while let Ok(handle) = tasks_keeper_receiver.recv() {
                handle.await.unwrap();
            }
        })
    }

    /// Just to reduce [`Client::connect`] nesting.
    async fn connect_public_key_send_match_arm(
        socket: Arc<UdpSocket>,
        buf: [u8; 1024],
        client_private_key: EphemeralSecret,
        message: SerializedPacketList,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        runtime: Arc<Runtime>,
        remote_addr: SocketAddr,
        sent_time: Instant,
    ) -> Result<ConnectResult, ConnectError> {
        let mut server_public_key: [u8; 32] = [0; 32];
        server_public_key.copy_from_slice(&buf[1..33]);

        let mut authentication_bytes = Vec::with_capacity(1 + 32 + message.bytes.len());
        authentication_bytes.push(MessageChannel::AUTH_MESSAGE);
        authentication_bytes.extend_from_slice(&server_public_key);
        authentication_bytes.extend(message.bytes);

        let server_public_key = PublicKey::from(server_public_key);
        let shared_key = client_private_key.diffie_hellman(&server_public_key);
        let cipher = ChaChaPoly1305::new(Key::from_slice(shared_key.as_bytes()));

        let (tasks_keeper_sender, tasks_keeper_receiver) = crossbeam_channel::unbounded();
        let (reason_to_disconnect_sender, reason_to_disconnect_receiver) =
            crossbeam_channel::bounded(1);

        let (receiving_bytes_sender, receiving_bytes_receiver) = crossbeam_channel::unbounded();
        let (packets_to_send_sender, packets_to_send_receiver) = crossbeam_channel::unbounded();
        let (message_part_confirmation_sender, message_part_confirmation_receiver) =
            crossbeam_channel::unbounded();
        let (shared_socket_bytes_send_sender, shared_socket_bytes_send_receiver) =
            crossbeam_channel::unbounded();

        let messaging = Arc::new(RwLock::new(ConnectedServerMessaging {
            cipher,
            pending_confirmation: BTreeMap::new(),
            incoming_message: MessagePartMap::new(
                messaging_properties.initial_next_message_part_id,
            ),
            tick_bytes_len: 0,
            last_received_message_instant: Instant::now(),
            received_messages: Vec::new(),
            packet_loss_rtt_calculator: RttCalculator::new(messaging_properties.initial_latency),
            average_packet_loss_rtt: messaging_properties.initial_latency,
            latency_monitor: DurationMonitor::filled_with(messaging_properties.initial_latency, 16),
            message_part_confirmation_sender,
            shared_socket_bytes_send_sender,
        }));

        let connected_server = ConnectedServer {
            addr: remote_addr,
            messaging: Arc::clone(&messaging),
            last_messaging_write: RwLock::new(Instant::now()),
            average_latency: RwLock::new(messaging_properties.initial_latency),
            receiving_bytes_sender,
            packets_to_send_sender,
        };

        let runtime_clone = Arc::clone(&runtime);

        let client = Arc::new(Client {
            socket: Arc::clone(&socket),
            runtime,
            tasks_keeper_handle: Client::create_async_tasks_keeper(
                runtime_clone,
                tasks_keeper_receiver,
            ),
            tasks_keeper_sender,
            tick_state: RwLock::new(ClientTickState::TickStartPending),
            packet_registry: packet_registry.clone(),
            messaging_properties: Arc::clone(&messaging_properties),
            read_handler_properties: Arc::clone(&read_handler_properties),
            connected_server,
            reason_to_disconnect_sender,
            reason_to_disconnect_receiver,
            disconnect_reason: RwLock::new(None),
        });

        let tick_packet_serialized = packet_registry.serialize(&ClientTickEndPacket).unwrap();

        let connected_server = &client.connected_server;
        client.send_packet_serialized(tick_packet_serialized.clone());
        connected_server.packets_to_send_sender.send(None).unwrap();

        let client_downgraded = Arc::downgrade(&client);
        let messaging_clone = Arc::clone(&messaging);
        client.create_async_task(async move {
            ConnectedServer::create_receiving_bytes_handler(
                client_downgraded,
                messaging_clone,
                receiving_bytes_receiver,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&client);
        let messaging_downgraded = Arc::downgrade(&messaging);
        let initial_next_message_part_id = client.messaging_properties.initial_next_message_part_id;
        client.create_async_task(async move {
            ConnectedServer::create_packets_to_send_handler(
                client_downgraded,
                messaging_downgraded,
                packets_to_send_receiver,
                initial_next_message_part_id,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&client);
        client.create_async_task(async move {
            ConnectedServer::create_message_part_confirmation_handler(
                client_downgraded,
                message_part_confirmation_receiver,
            )
            .await;
        });

        let client_downgraded = Arc::downgrade(&client);
        client.create_async_task(async move {
            ConnectedServer::create_shared_socket_bytes_send_handler(
                client_downgraded,
                shared_socket_bytes_send_receiver,
            )
            .await;
        });

        loop {
            let now = Instant::now();
            socket.send(&authentication_bytes).await?;

            // TODO: add value
            let read_timeout = Duration::from_secs(3);
            let pre_read_next_bytes_result =
                Client::pre_read_next_bytes(&socket, read_timeout).await;

            match pre_read_next_bytes_result {
                Ok(result) => {
                    //TODO: use this
                    let read_result = client.read_next_bytes(result).await;

                    match client.tick_start() {
                        ClientTickResult::ReceivedMessage(message) => {
                            client.try_check_read_handler();
                            return Ok(ConnectResult { client, message });
                        }
                        ClientTickResult::PendingMessage => (),
                        ClientTickResult::Disconnected => {
                            return Err(ConnectError::Disconnected(
                                client.take_disconnect_reason().unwrap(),
                            ))
                        }
                        ClientTickResult::WriteLocked => (),
                    }
                }
                Err(_) => {
                    if now - sent_time > messaging_properties.timeout_interpretation {
                        return Err(ConnectError::Timeout);
                    }
                }
            }
        }
    }

    fn try_check_read_handler(self: &Arc<Self>) {
        if let Ok(mut active_count) = self.read_handler_properties.active_count.try_write() {
            if *active_count < self.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&self);
                self.create_async_task(async move {
                    Client::create_read_handler(downgraded_server).await;
                });
            }
        }
    }

    async fn create_read_handler(weak_client: Weak<Client>) {
        let mut was_used = false;
        loop {
            if let Some(client) = weak_client.upgrade() {
                if *client.read_handler_properties.active_count.write().unwrap()
                    > client.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        client.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break;
                } else {
                    let read_timeout = client.read_handler_properties.timeout;
                    let socket = Arc::clone(&client.socket);
                    drop(client);
                    let pre_read_next_bytes_result =
                        Client::pre_read_next_bytes(&socket, read_timeout).await;
                    if let Some(client) = weak_client.upgrade() {
                        match pre_read_next_bytes_result {
                            Ok(result) => {
                                if !was_used {
                                    was_used = true;
                                    let mut surplus_count = client
                                        .read_handler_properties
                                        .active_count
                                        .write()
                                        .unwrap();
                                    *surplus_count -= 1;
                                }

                                //TODO: use this
                                let read_result = client.read_next_bytes(result).await;
                            }
                            Err(_) => {
                                if was_used {
                                    was_used = false;
                                    let mut surplus_count = client
                                        .read_handler_properties
                                        .active_count
                                        .write()
                                        .unwrap();
                                    *surplus_count += 1;
                                }
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }
    }

    async fn pre_read_next_bytes(
        socket: &Arc<UdpSocket>,
        read_timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let pre_read_next_bytes_result: Result<io::Result<Vec<u8>>, tokio::time::error::Elapsed> =
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
        let mut messaging = self.connected_server.messaging.write().unwrap();
        // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
        messaging.tick_bytes_len += bytes.len() + 8 + 20;
        if messaging.tick_bytes_len > self.messaging_properties.max_client_tick_bytes_len {
            ReadServerBytesResult::ServerMaxTickByteLenOverflow
        } else {
            let _ = self.connected_server.receiving_bytes_sender.send(bytes);
            ReadServerBytesResult::ServerReceivedBytes
        }
    }
}
