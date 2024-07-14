use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
use dashmap::{DashMap, DashSet};
use rand::rngs::OsRng;
use tokio::{net::UdpSocket, runtime::Runtime, task::JoinHandle, time::timeout};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::{
    messages::{
        DeserializedMessage, MessageId, MessagePart, MessagePartId, MessagePartMap,
        MessagePartMapTryInsertResult, MessagePartMapTryReadResult, MINIMAL_PART_BYTES_SIZE,
    },
    packets::{
        DeserializedPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList,
        ServerTickEndPacket,
    },
    utils::{DurationMonitor, RttCalculator},
};

use super::{
    JustifiedRejectionContext, MessageChannel, MessagingProperties, ReadHandlerProperties,
    SentMessagePart, MESSAGE_CHANNEL_SIZE,
};

/// Possible results when receiving bytes by clients.
#[derive(Debug)]
enum ReadClientBytesResult {
    /// The received byte length is insufficient.
    InsufficientBytesLen,
    /// Disconnect confirmation from the client is done.
    DoneDisconnectConfirm,
    /// Disconnect confirmation from the client is pending.
    PendingDisconnectConfirm,
    /// Client handle is ignored.
    IgnoredClientHandle,
    /// Address is in the authentication process.
    AddrInAuth,
    /// The byte length for authentication is insufficient.
    AuthInsufficientBytesLen,
    /// The client has exceeded the maximum tick byte length.
    ClientMaxTickByteLenOverflow,
    /// Bytes were successfully received from the client.
    ClientReceivedBytes,
    /// Pending authentication is completed.
    DonePendingAuth,
    /// The pending authentication is invalid.
    InvalidPendingAuth,
    /// The pending authentication is still in process.
    PendingPendingAuth,
    /// The public key has been successfully sent.
    PublicKeySend,
    /// The public key send operation is invalid.
    InvalidPublicKeySend,
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
    ByteSendError,
    /// Client was manually disconnected.
    ManualDisconnect,
    /// Client disconnected itself.
    DisconnectRequest,
}

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
    pub server: Arc<Server>,
}

/// Server tick flow state.
#[derive(Debug, PartialEq, Eq)]
enum ServerTickState {
    /// Next call should be [`Server::tick_start`].
    TickStartPending,
    /// Next call should be [`Server::tick_end`].
    TickEndPending,
}

/// Result when calling [`Server::tick_start`].
pub struct ServerTickResult {
    pub received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>>,
    pub to_auth: HashMap<SocketAddr, AddrToAuth>,
    pub disconnected: HashMap<SocketAddr, ClientDisconnectReason>,
}

/// Pending auth properties of a addr that is trying to connect.
///
/// Intended to use used inside [`Server#pending_auth`].
struct AddrPendingAuthSend {
    /// The instant that the request was received.
    received_time: Instant,
    /// The last instant that the bytes were sent.
    last_sent_time: Option<Instant>,
    /// Random private key created inside the server.
    server_private_key: EphemeralSecret,
    /// Random public key created inside the server. Sent to the addr.
    server_public_key: PublicKey,
    /// Random public key created by the addr. Sent by the addr.
    addr_public_key: PublicKey,
    /// Finished bytes, with the channel and the server public key.
    finished_bytes: Vec<u8>,
}

/// Addr to auth properties, after a [`AddrPendingAuthSend`] is confirmed,
/// the next step is read the message of the addr, and authenticate it or no.
pub struct AddrToAuth {
    shared_key: SharedSecret,
    pub message: Vec<DeserializedPacket>,
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
        if list.bytes.len() > 1024 - 1 {
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

/// Messaging fields of [`ConnectedClient`].
///
/// Intended to be used with [`Arc`] and [`RwLock`].
struct ConnectedClientMessaging {
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

/// Properties of a client that is connected to the server.
///
/// Intended to be used inside `ServerAsync`.
pub struct ConnectedClient {
    /// The socket address of the connected client.
    addr: SocketAddr,

    /// Messaging-related properties wrapped in an `Arc` and `RwLock`.
    messaging: Arc<RwLock<ConnectedClientMessaging>>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,

    /// Sender for receiving bytes.
    receiving_bytes_sender: crossbeam_channel::Sender<Vec<u8>>,

    /// Sender for packets to be sent.
    packets_to_send_sender: crossbeam_channel::Sender<Option<SerializedPacket>>,
}

impl ConnectedClient {
    /// # Returns
    /// The average time of messaging response of this client after a server message.
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    /// # Returns
    /// The total size of the incoming message map.
    pub fn stored_incoming_message_size(&self) -> usize {
        self.messaging.read().unwrap().incoming_message.total_size()
    }

    async fn create_receiving_bytes_handler(
        server: Weak<Server>,
        addr: SocketAddr,
        messaging: Arc<RwLock<ConnectedClientMessaging>>,
        receiving_bytes_receiver: crossbeam_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv() {
            if let Some(server) = server.upgrade() {
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
                            let _ = server.clients_to_disconnect_sender.send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
                            break 'l1;
                        }
                    }
                    MessageChannel::MESSAGE_PART_SEND => {
                        // 12 for nonce
                        if bytes.len() < MESSAGE_CHANNEL_SIZE + MINIMAL_PART_BYTES_SIZE + 12 {
                            let _ = server.clients_to_disconnect_sender.send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
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
                                            match messaging.incoming_message.try_read(&server.packet_registry){
                                                MessagePartMapTryReadResult::PendingParts => break 'l2,
                                                MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                                    let _ = server.clients_to_disconnect_sender.send((
                                                        addr,
                                                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
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
                                let _ = server.clients_to_disconnect_sender.send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        } else {
                            let _ = server.clients_to_disconnect_sender.send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
                            break 'l1;
                        }
                    }
                    MessageChannel::DISCONNECT_REQUEST => {
                        let _ = server
                            .clients_to_disconnect_sender
                            .send((addr, (ClientDisconnectReason::DisconnectRequest, None)));
                        break 'l1;
                    }
                    MessageChannel::AUTH_MESSAGE => {
                        // Client probably multiple authentication packets before being authenticated
                    }
                    _ => {
                        let _ = server.clients_to_disconnect_sender.send((
                            addr,
                            (ClientDisconnectReason::InvalidProtocolCommunication, None),
                        ));
                        break 'l1;
                    }
                }
            }
        }
    }

    async fn create_packets_to_send_handler(
        server: Weak<Server>,
        messaging: Weak<RwLock<ConnectedClientMessaging>>,
        packets_to_send_receiver: crossbeam_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        while let Ok(serialized_packet) = packets_to_send_receiver.recv() {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(server) = server.upgrade() {
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
        server: Weak<Server>,
        addr: SocketAddr,
        message_part_confirmation_receiver: crossbeam_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv() {
            if let Some(server) = server.upgrade() {
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
                if server.socket.send_to(&bytes, addr).await.is_err() {
                    let _ = server.clients_to_disconnect_sender.send((
                        addr,
                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                    ));
                    break;
                }
            }
        }
    }

    async fn create_shared_socket_bytes_send_handler(
        server: Weak<Server>,
        addr: SocketAddr,
        shared_socket_bytes_send_receiver: crossbeam_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        while let Ok(bytes) = shared_socket_bytes_send_receiver.recv() {
            if let Some(server) = server.upgrade() {
                if server.socket.send_to(&bytes, addr).await.is_err() {
                    let _ = server.clients_to_disconnect_sender.send((
                        addr,
                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                    ));
                    break;
                }
            }
        }
    }
}

/// Properties of the server.
///
/// Intended to be used with [`Arc`].
pub struct Server {
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: crossbeam_channel::Sender<JoinHandle<()>>,
    /// Sender for signaling the reading of ignored addresses' reasons.
    ignored_addrs_asking_reason_read_signal_sender: crossbeam_channel::Sender<()>,
    /// Sender for addresses to be authenticated.
    clients_to_auth_sender: crossbeam_channel::Sender<(SocketAddr, AddrToAuth)>,
    /// Sender for addresses to be disconnected.
    clients_to_disconnect_sender: crossbeam_channel::Sender<(
        SocketAddr,
        (ClientDisconnectReason, Option<JustifiedRejectionContext>),
    )>,
    /// Sender for resending pending rejection confirmations.
    pending_rejection_confirm_resend_sender: crossbeam_channel::Sender<SocketAddr>,
    /// Sender for resending authentication bytes, like the server public key.
    pending_auth_resend_sender: crossbeam_channel::Sender<SocketAddr>,

    /// Receiver for addresses to be authenticated.
    clients_to_auth_receiver: crossbeam_channel::Receiver<(SocketAddr, AddrToAuth)>,

    /// Receiver for addresses to be disconnected.
    clients_to_disconnect_receiver: crossbeam_channel::Receiver<(
        SocketAddr,
        (ClientDisconnectReason, Option<JustifiedRejectionContext>),
    )>,

    /// Task handle of the receiver.
    tasks_keeper_handle: JoinHandle<()>,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,
    /// The runtime for asynchronous operations.
    runtime: Arc<Runtime>,
    /// Actual state of server periodic tick flow.
    tick_state: RwLock<ServerTickState>,

    /// The registry for packets.
    pub packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    pub messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    pub read_handler_properties: Arc<ReadHandlerProperties>,
    /// Properties for the internal server management.
    pub server_properties: Arc<ServerProperties>,

    /// Map of connected clients, keyed by their socket address.
    connected_clients: DashMap<SocketAddr, ConnectedClient>,

    /// Map of ignored addresses with reasons for ignoring them.
    ignored_addrs: DashMap<SocketAddr, IgnoredAddrReason>,
    /// Map of temporarily ignored addresses with the time until they are ignored.
    temporary_ignored_addrs: DashMap<SocketAddr, Instant>,
    /// Set of addresses asking for the reason they are ignored.
    ignored_addrs_asking_reason: DashSet<SocketAddr>,

    /// Set of addresses in the authentication process.
    addrs_in_auth: DashSet<SocketAddr>,
    /// Lock-protected set of assigned addresses in authentication.
    assigned_addrs_in_auth: RwLock<HashSet<SocketAddr>>,
    /// Map of pending authentication addresses.
    pending_auth: DashMap<SocketAddr, AddrPendingAuthSend>,

    /// Map of pending rejection confirmations.
    pending_rejection_confirm: DashMap<SocketAddr, JustifiedRejectionContext>,
}

impl Server {
    /// Bind a [`UdpSocket´], to create a new Server instance
    pub async fn bind(
        addr: SocketAddr,
        packet_registry: Arc<PacketRegistry>,
        messaging_properties: Arc<MessagingProperties>,
        read_handler_properties: Arc<ReadHandlerProperties>,
        server_properties: Arc<ServerProperties>,
        runtime: Arc<Runtime>,
    ) -> io::Result<BindResult> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);

        let (tasks_keeper_sender, tasks_keeper_receiver) = crossbeam_channel::unbounded();
        let (pending_auth_resend_sender, pending_auth_resend_receiver) =
            crossbeam_channel::unbounded();
        let (pending_rejection_confirm_resend_sender, pending_rejection_confirm_resend_receiver) =
            crossbeam_channel::unbounded();
        let (
            ignored_addrs_asking_reason_read_signal_sender,
            ignored_addrs_asking_reason_read_signal_receiver,
        ) = crossbeam_channel::unbounded();
        let (clients_to_auth_sender, clients_to_auth_receiver) = crossbeam_channel::unbounded();
        let (clients_to_disconnect_sender, clients_to_disconnect_receiver) =
            crossbeam_channel::unbounded();

        let runtime_clone = Arc::clone(&runtime);

        let server = Arc::new(Server {
            tasks_keeper_sender,
            ignored_addrs_asking_reason_read_signal_sender,
            clients_to_auth_sender,
            clients_to_disconnect_sender,
            pending_rejection_confirm_resend_sender,
            pending_auth_resend_sender,

            clients_to_auth_receiver,
            clients_to_disconnect_receiver,

            tasks_keeper_handle: Server::create_async_tasks_keeper(
                runtime_clone,
                tasks_keeper_receiver,
            ),

            socket,
            runtime,
            tick_state: RwLock::new(ServerTickState::TickStartPending),

            packet_registry,
            messaging_properties,
            read_handler_properties,
            server_properties,

            connected_clients: DashMap::new(),
            ignored_addrs: DashMap::new(),
            temporary_ignored_addrs: DashMap::new(),
            ignored_addrs_asking_reason: DashSet::new(),
            addrs_in_auth: DashSet::new(),
            assigned_addrs_in_auth: RwLock::new(HashSet::new()),
            pending_auth: DashMap::new(),
            pending_rejection_confirm: DashMap::new(),
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            Server::create_pending_auth_resend_handler(
                server_downgraded,
                pending_auth_resend_receiver,
            )
            .await;
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            Server::create_pending_rejection_confirm_resend_handler(
                server_downgraded,
                pending_rejection_confirm_resend_receiver,
            )
            .await;
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            Server::create_ignored_addrs_asking_reason_handler(
                server_downgraded,
                ignored_addrs_asking_reason_read_signal_receiver,
            )
            .await;
        });

        Ok(BindResult { server })
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
    pub fn tick_start(self: &Arc<Self>) -> ServerTickResult {
        {
            let mut tick_state = self.tick_state.write().unwrap();
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

        let mut assigned_addrs_in_auth = self.assigned_addrs_in_auth.write().unwrap();
        let dispatched_assigned_addrs_in_auth = std::mem::take(&mut *assigned_addrs_in_auth);
        for addr in dispatched_assigned_addrs_in_auth {
            self.addrs_in_auth.remove(&addr).unwrap();
        }

        self.pending_auth.retain(|_, pending_auth_send| {
            now - pending_auth_send.received_time < self.messaging_properties.timeout_interpretation
        });
        for context in self.pending_auth.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time
                    < self
                        .server_properties
                        .pending_auth_packet_loss_interpretation
                {
                    continue;
                }
            }
            self.pending_auth_resend_sender
                .send(context.key().clone())
                .unwrap();
        }

        self.temporary_ignored_addrs.retain(|addr, until_to| {
            if now < *until_to {
                true
            } else {
                self.ignored_addrs.remove(addr);
                false
            }
        });

        let mut received_messages: HashMap<SocketAddr, Vec<DeserializedMessage>> = HashMap::new();
        let mut to_auth: HashMap<SocketAddr, AddrToAuth> = HashMap::new();
        let mut disconnected: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

        let mut addrs_to_disconnect: HashMap<
            SocketAddr,
            (ClientDisconnectReason, Option<JustifiedRejectionContext>),
        > = HashMap::new();

        while let Ok((addr, addr_to_auth)) = self.clients_to_auth_receiver.try_recv() {
            to_auth.insert(addr, addr_to_auth);
        }

        while let Ok((addr, reason)) = self.clients_to_disconnect_receiver.try_recv() {
            if !addrs_to_disconnect.contains_key(&addr) {
                addrs_to_disconnect.insert(addr, reason);
            }
        }

        'l1: for client in self.connected_clients.iter() {
            if addrs_to_disconnect.contains_key(client.key()) {
                continue 'l1;
            }
            if let Ok(mut messaging) = client.messaging.try_write() {
                *client.last_messaging_write.write().unwrap() = now;
                *client.average_latency.write().unwrap() =
                    messaging.latency_monitor.average_value();

                let average_packet_loss_rtt = messaging.average_packet_loss_rtt;
                let mut messages_to_resend: Vec<Arc<Vec<u8>>> = Vec::new();

                for (sent_instant, pending_part_id_map) in
                    messaging.pending_confirmation.values_mut()
                {
                    if now - *sent_instant > self.messaging_properties.timeout_interpretation {
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
                    messaging
                        .shared_socket_bytes_send_sender
                        .send(finished_bytes)
                        .unwrap();
                }

                if !messaging.received_messages.is_empty() {
                    let messages = std::mem::replace(&mut messaging.received_messages, Vec::new());
                    messaging.tick_bytes_len = 0;
                    received_messages.insert(client.key().clone(), messages);
                } else if now - messaging.last_received_message_instant
                    >= self.messaging_properties.timeout_interpretation
                {
                    addrs_to_disconnect.insert(
                        client.key().clone(),
                        (ClientDisconnectReason::MessageReceiveTimeout, None),
                    );
                    continue 'l1;
                }
            } else if now - *client.last_messaging_write.read().unwrap()
                >= self.messaging_properties.timeout_interpretation
            {
                addrs_to_disconnect.insert(
                    client.key().clone(),
                    (ClientDisconnectReason::WriteUnlockTimeout, None),
                );
                continue 'l1;
            }
        }

        self.pending_rejection_confirm.retain(|_, context| {
            now - context.rejection_instant
                < self.messaging_properties.disconnect_reason_resend_cancel
        });
        for context in self.pending_rejection_confirm.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time < self.messaging_properties.disconnect_reason_resend_delay {
                    continue;
                }
            }
            self.pending_rejection_confirm_resend_sender
                .send(context.key().clone())
                .unwrap();
        }

        for (addr, (reason, context)) in addrs_to_disconnect {
            self.connected_clients.remove(&addr).unwrap();
            if let Some(context) = context {
                self.pending_rejection_confirm.insert(addr.clone(), context);
            }
            disconnected.insert(addr, reason);
        }

        for addr in to_auth.keys() {
            assigned_addrs_in_auth.insert(addr.clone());
        }

        self.ignored_addrs_asking_reason_read_signal_sender
            .send(())
            .unwrap();

        self.try_check_read_handler();

        ServerTickResult {
            received_messages,
            to_auth,
            disconnected,
        }
    }

    /// Server periodic tick end.
    ///
    /// It handles:
    /// - Unification of packages to be sent to clients.
    ///
    /// # Panics
    /// If is not called after [`Server::tick_start`]
    pub fn tick_end(self: &Arc<Self>) {
        {
            let mut tick_state = self.tick_state.write().unwrap();
            if *tick_state != ServerTickState::TickEndPending {
                panic!(
                    "Invalid server tick state, next pending is {:?}",
                    tick_state
                );
            } else {
                *tick_state = ServerTickState::TickStartPending;
            }
        }

        let tick_packet_serialized = self
            .packet_registry
            .serialize(&ServerTickEndPacket)
            .unwrap();

        for client in self.connected_clients.iter() {
            self.send_packet_serialized(&client, tick_packet_serialized.clone());
            client.packets_to_send_sender.send(None).unwrap();
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
    pub fn authenticate(self: &Arc<Self>, addr: SocketAddr, addr_to_auth: AddrToAuth) {
        if self.connected_clients.contains_key(&addr) {
            panic!("Addr is already connected.",)
        } else if !self.assigned_addrs_in_auth.write().unwrap().remove(&addr) {
            panic!("Addr was not marked to be authenticated in the last server tick.",)
        } else {
            self.addrs_in_auth.remove(&addr).unwrap();

            let (receiving_bytes_sender, receiving_bytes_receiver) = crossbeam_channel::unbounded();
            let (packets_to_send_sender, packets_to_send_receiver) = crossbeam_channel::unbounded();
            let (message_part_confirmation_sender, message_part_confirmation_receiver) =
                crossbeam_channel::unbounded();
            let (shared_socket_bytes_send_sender, shared_socket_bytes_send_receiver) =
                crossbeam_channel::unbounded();

            let now = Instant::now();

            let messaging = Arc::new(RwLock::new(ConnectedClientMessaging {
                cipher: ChaChaPoly1305::new(Key::from_slice(addr_to_auth.shared_key.as_bytes())),
                pending_confirmation: BTreeMap::new(),
                incoming_message: MessagePartMap::new(
                    self.messaging_properties.initial_next_message_part_id,
                ),
                tick_bytes_len: 0,
                received_messages: Vec::new(),
                last_received_message_instant: now,
                packet_loss_rtt_calculator: RttCalculator::new(
                    self.messaging_properties.initial_latency,
                ),
                average_packet_loss_rtt: self.messaging_properties.initial_latency,
                latency_monitor: DurationMonitor::filled_with(
                    self.messaging_properties.initial_latency,
                    16,
                ),
                message_part_confirmation_sender,
                shared_socket_bytes_send_sender,
            }));

            let connected_client = ConnectedClient {
                addr,
                messaging: Arc::clone(&messaging),
                last_messaging_write: RwLock::new(now),
                average_latency: RwLock::new(self.messaging_properties.initial_latency),
                receiving_bytes_sender,
                packets_to_send_sender,
            };

            let server_downgraded = Arc::downgrade(&self);
            let messaging_clone = Arc::clone(&messaging);
            self.create_async_task(async move {
                ConnectedClient::create_receiving_bytes_handler(
                    server_downgraded,
                    addr,
                    messaging_clone,
                    receiving_bytes_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&self);
            let messaging_downgraded = Arc::downgrade(&messaging);
            let initial_next_message_part_id =
                self.messaging_properties.initial_next_message_part_id;
            self.create_async_task(async move {
                ConnectedClient::create_packets_to_send_handler(
                    server_downgraded,
                    messaging_downgraded,
                    packets_to_send_receiver,
                    initial_next_message_part_id,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&self);
            self.create_async_task(async move {
                ConnectedClient::create_message_part_confirmation_handler(
                    server_downgraded,
                    addr,
                    message_part_confirmation_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&self);
            self.create_async_task(async move {
                ConnectedClient::create_shared_socket_bytes_send_handler(
                    server_downgraded,
                    addr,
                    shared_socket_bytes_send_receiver,
                )
                .await;
            });

            self.connected_clients.insert(addr, connected_client);
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
    pub fn refuse(
        self: &Arc<Self>,
        addr: SocketAddr,
        _addr_to_auth: AddrToAuth,
        message: SerializedPacketList,
    ) {
        if self.connected_clients.contains_key(&addr) {
            panic!("Addr is already connected.",)
        } else if !self.assigned_addrs_in_auth.write().unwrap().remove(&addr) {
            panic!("Addr was not marked to be authenticated in the last server tick.",)
        } else {
            self.pending_rejection_confirm.insert(
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
    ///
    pub fn disconnect_from(
        self: &Arc<Self>,
        client: &ConnectedClient,
        message: Option<SerializedPacketList>,
    ) {
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
        self.clients_to_disconnect_sender
            .send((
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
    pub fn ignore_addr(&self, addr: SocketAddr, reason: IgnoredAddrReason) {
        self.temporary_ignored_addrs.remove(&addr);
        self.ignored_addrs.insert(addr, reason);
    }

    /// The messages of this addr will be ignored, for the expected time, then,
    /// it will be cleared and the addr will be able to send messages for the server.
    ///
    /// If that client is already ignored, the reason will be replaced.
    pub fn ignore_addr_temporary(
        &self,
        addr: SocketAddr,
        reason: IgnoredAddrReason,
        until_to: Instant,
    ) {
        self.ignored_addrs.insert(addr, reason);
        self.temporary_ignored_addrs.insert(addr, until_to);
    }

    /// Removes the specified addr from the ignored list, even if it is temporary ignored.
    pub fn remove_ignore_addr(&self, addr: &SocketAddr) {
        self.ignored_addrs.remove(addr);
        self.temporary_ignored_addrs.remove(addr);
    }

    /// # Returns
    /// Connected client if found.
    pub fn get_connected_client(
        &self,
        addr: &SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<SocketAddr, ConnectedClient>> {
        self.connected_clients.get(addr)
    }

    /// # Returns
    /// Iterator with the clients connected to the server.
    pub fn connected_clients_iter(
        &self,
    ) -> dashmap::iter::Iter<
        SocketAddr,
        ConnectedClient,
        std::hash::RandomState,
        DashMap<SocketAddr, ConnectedClient>,
    > {
        self.connected_clients.iter()
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
    /// let server: Arc<Server> = ...;
    /// let addr: SocketAddr = ...;
    /// let client = server.get_connected_client(&addr).unwrap();
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// server.send_packet(&client, &packet);
    /// ```
    pub fn send_packet<P: Packet>(&self, client: &ConnectedClient, packet: &P) {
        let serialized = self
            .packet_registry
            .serialize(packet)
            .expect("Failed to serialize packet.");
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
    /// let server: Arc<Server> = ...;
    /// let addr: SocketAddr = ...;
    /// let client = server.get_connected_client(&addr).unwrap();
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// let packet_serialized = server.packet_registry.serialize(&packet).expect("Failed to serialize packet.");
    /// server.send_packet_serialized(&client, &packet_serialized);
    /// ```
    pub fn send_packet_serialized(
        &self,
        client: &ConnectedClient,
        packet_serialized: SerializedPacket,
    ) {
        client
            .packets_to_send_sender
            .send(Some(packet_serialized))
            .unwrap();
    }

    /// TODO:
    pub fn disconnect_detached(self: Arc<Self>) {
        Arc::clone(&self).create_async_task(async move {
            let disconnect_request_bytes = vec![MessageChannel::DISCONNECT_REQUEST];
            for client in self.connected_clients.iter() {
                let _ = self
                    .socket
                    .send_to(&disconnect_request_bytes, client.addr)
                    .await;
            }
            todo!();
        });
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

    async fn create_pending_auth_resend_handler(
        server: Weak<Server>,
        pending_auth_resend_receiver: crossbeam_channel::Receiver<SocketAddr>,
    ) {
        while let Ok(addr) = pending_auth_resend_receiver.recv() {
            if let Some(server) = server.upgrade() {
                if let Some(mut context) = server.pending_auth.get_mut(&addr) {
                    context.last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            }
        }
    }

    async fn create_pending_rejection_confirm_resend_handler(
        server: Weak<Server>,
        pending_rejection_confirm_resend_receiver: crossbeam_channel::Receiver<SocketAddr>,
    ) {
        while let Ok(addr) = pending_rejection_confirm_resend_receiver.recv() {
            if let Some(server) = server.upgrade() {
                if let Some(mut context) = server.pending_rejection_confirm.get_mut(&addr) {
                    context.last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            }
        }
    }

    async fn create_ignored_addrs_asking_reason_handler(
        server: Weak<Server>,
        ignored_addrs_asking_reason_read_signal_receiver: crossbeam_channel::Receiver<()>,
    ) {
        while let Ok(_) = ignored_addrs_asking_reason_read_signal_receiver.recv() {
            if let Some(server) = server.upgrade() {
                for addr in server.ignored_addrs_asking_reason.iter() {
                    if let Some(reason) = server.ignored_addrs.get(&addr) {
                        if let Some(finished_bytes) = &reason.finished_bytes {
                            let _ = server.socket.send_to(&finished_bytes, addr.clone());
                        }
                    }
                }
                server.ignored_addrs_asking_reason.clear();
            }
        }
    }

    fn try_check_read_handler(self: &Arc<Self>) {
        if let Ok(mut active_count) = self.read_handler_properties.active_count.try_write() {
            if *active_count < self.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&self);
                self.create_async_task(async move {
                    Server::create_read_handler(downgraded_server).await;
                });
            }
        }
    }

    async fn create_read_handler(weak_server: Weak<Server>) {
        let mut was_used = false;
        loop {
            if let Some(server) = weak_server.upgrade() {
                if *server.read_handler_properties.active_count.write().unwrap()
                    > server.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        server.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break;
                } else {
                    let read_timeout = server.read_handler_properties.timeout;
                    let socket = Arc::clone(&server.socket);
                    drop(server);

                    let pre_read_next_bytes_result =
                        Server::pre_read_next_bytes(&socket, read_timeout).await;

                    if let Some(server) = weak_server.upgrade() {
                        match pre_read_next_bytes_result {
                            Ok(result) => {
                                if !was_used {
                                    was_used = true;
                                    let mut surplus_count = server
                                        .read_handler_properties
                                        .active_count
                                        .write()
                                        .unwrap();
                                    *surplus_count -= 1;
                                }

                                //TODO: use this
                                let read_result = server.read_next_bytes(result).await;
                            }
                            Err(_) => {
                                if was_used {
                                    was_used = false;
                                    let mut surplus_count = server
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
    ) -> io::Result<(SocketAddr, Vec<u8>)> {
        let pre_read_next_bytes_result: Result<
            io::Result<(SocketAddr, Vec<u8>)>,
            tokio::time::error::Elapsed,
        > = timeout(read_timeout, async move {
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
            ReadClientBytesResult::InsufficientBytesLen
        } else if self.pending_rejection_confirm.contains_key(&addr) {
            if bytes[0] == MessageChannel::REJECTION_CONFIRM {
                self.pending_rejection_confirm.remove(&addr);
                ReadClientBytesResult::DoneDisconnectConfirm
            } else {
                ReadClientBytesResult::PendingDisconnectConfirm
            }
        } else if let Some(reason) = self.ignored_addrs.get(&addr) {
            if reason.finished_bytes.is_some()
                && self.ignored_addrs_asking_reason.len()
                    < self.server_properties.max_ignored_addrs_asking_reason
            {
                self.ignored_addrs_asking_reason.insert(addr);
            }
            ReadClientBytesResult::IgnoredClientHandle
        } else if let Some(client) = self.connected_clients.get(&addr) {
            let mut messaging = client.messaging.write().unwrap();
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 20;
            if messaging.tick_bytes_len > self.messaging_properties.max_client_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.send(bytes);
                ReadClientBytesResult::ClientReceivedBytes
            }
        } else if self.addrs_in_auth.contains(&addr) {
            ReadClientBytesResult::AddrInAuth
        } else if let Some((_, pending_auth_send)) = self.pending_auth.remove(&addr) {
            if bytes[0] == MessageChannel::AUTH_MESSAGE {
                // 32 for public key, and 1 for the smallest possible serialized packet
                if bytes.len() < MESSAGE_CHANNEL_SIZE + 32 + 1 {
                    ReadClientBytesResult::AuthInsufficientBytesLen
                } else {
                    let packets =
                        DeserializedPacket::deserialize_list(&bytes[33..], &self.packet_registry);
                    if let Ok(message) = packets {
                        let mut sent_server_public_key: [u8; 32] = [0; 32];
                        sent_server_public_key.copy_from_slice(&bytes[1..33]);
                        let sent_server_public_key = PublicKey::from(sent_server_public_key);

                        if sent_server_public_key != pending_auth_send.server_public_key {
                            ReadClientBytesResult::InvalidPendingAuth
                        } else {
                            self.addrs_in_auth.insert(addr.clone());
                            let _ = self.clients_to_auth_sender.send((
                                addr,
                                AddrToAuth {
                                    shared_key: pending_auth_send
                                        .server_private_key
                                        .diffie_hellman(&pending_auth_send.addr_public_key),
                                    message,
                                },
                            ));
                            ReadClientBytesResult::DonePendingAuth
                        }
                    } else {
                        self.ignore_addr_temporary(
                            addr,
                            IgnoredAddrReason::without_reason(),
                            Instant::now() + Duration::from_secs(5),
                        );
                        ReadClientBytesResult::InvalidPendingAuth
                    }
                }
            } else {
                self.pending_auth.insert(addr, pending_auth_send);
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

            self.pending_auth.insert(
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
