use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce,
};
use dashmap::{DashMap, DashSet};
use rand::rngs::OsRng;
use tokio::{net::UdpSocket, runtime::Runtime, sync::Mutex, task::JoinHandle, time::timeout};
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
    DisconnectRequest(Vec<DeserializedPacket>),
}

/// General properties for the server management.
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

/// Messaging fields of [`ConnectedClient`].
///
/// Intended to be used with [`Mutex`].
struct ConnectedClientMessaging {
    /// Sender for message part confirmations.
    message_part_confirmation_sender: async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

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
}

/// Properties of a client that is connected to the server.
///
/// Intended to be used inside `ServerAsync` with [`Arc`].
pub struct ConnectedClient {
    /// Sender for receiving bytes.
    receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    
    /// Sender for packets to be sent.
    packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,

    /// The socket address of the connected client.
    addr: SocketAddr,

    /// Messaging-related properties wrapped in an [`Mutex`].
    messaging: Mutex<ConnectedClientMessaging>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,
}

impl ConnectedClient {
    /// # Returns
    /// The average time of messaging response of this client after a server message.
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    async fn create_receiving_bytes_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        client: Weak<ConnectedClient>,
        receiving_bytes_receiver: async_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Some(client) = client.upgrade() {
                    let mut messaging = client.messaging.lock().await;
                    match bytes[0] {
                        MessageChannel::MESSAGE_PART_CONFIRM => {
                            if bytes.len() == 3 {
                                let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                                if let Some((sent_instant, _)) =
                                    messaging.pending_confirmation.remove(&message_id)
                                {
                                    let delay = Instant::now() - sent_instant;
                                    messaging.latency_monitor.push(delay);
                                    messaging.average_packet_loss_rtt = messaging.packet_loss_rtt_calculator.update_rtt(
                                        &server.messaging_properties.packet_loss_rtt_properties,
                                        delay,
                                    );
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
                                        messaging.average_packet_loss_rtt = messaging.packet_loss_rtt_calculator.update_rtt(
                                            &server.messaging_properties.packet_loss_rtt_properties,
                                            delay,
                                        );
                                    }
                                }
                            } else {
                                drop(messaging);
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::MESSAGE_PART_SEND => {
                            // 12 for nonce
                            if bytes.len() < MESSAGE_CHANNEL_SIZE + MINIMAL_PART_BYTES_SIZE + 12 {
                                drop(messaging);
                                let _ = server.clients_to_disconnect_sender.try_send((
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
                                            .try_send((message_id, None));
                                        },
                                        MessagePartMapTryInsertResult::Stored => {
                                            'l2: loop {
                                                match messaging.incoming_message.try_read(&server.packet_registry){
                                                    MessagePartMapTryReadResult::PendingParts => break 'l2,
                                                    MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                                        let _ = server.clients_to_disconnect_sender.try_send((
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
                                                    .try_send((message_id, None));
                                            } else {
                                                let _ = messaging
                                                    .message_part_confirmation_sender
                                                    .try_send((message_id, Some(part_id)));
                                            }
                                        },
                                    }
                                } else {
                                    let _ = server.clients_to_disconnect_sender.try_send((
                                        addr,
                                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                    ));
                                    break 'l1;
                                }
                            } else {
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::REJECTION_JUSTIFICATION => {
                            // 4 for the minimal SerializedPacket
                            if bytes.len() < MESSAGE_CHANNEL_SIZE + 4 {
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            } else if let Ok(message) =
                                DeserializedPacket::deserialize_list(&bytes[1..], &server.packet_registry)
                            {
                                server.rejections_to_confirm.insert(addr.clone());
                                let _ = server
                                    .clients_to_disconnect_sender
                                    .try_send((addr, (ClientDisconnectReason::DisconnectRequest(message), None)));
                                break 'l1;
                            } else {
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::AUTH_MESSAGE => {
                            // Client probably multiple authentication packets before being authenticated
                        }
                        _ => {
                            let _ = server.clients_to_disconnect_sender.try_send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
                            break 'l1;
                        }
                    }
                } else {
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        } 
    }

    async fn create_packets_to_send_handler(
        server: Weak<ServerInternal>,
        client: Weak<ConnectedClient>,
        packets_to_send_receiver: async_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        'l1: while let Ok(serialized_packet) = packets_to_send_receiver.recv().await {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(server) = server.upgrade() {
                    if let Some(client) = client.upgrade() {
                        let mut messaging = client.messaging.lock().await;
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
                                .try_send(finished_bytes);
                        }

                        next_message_id = next_message_id.wrapping_add(1);
                    } else {
                        break 'l1;
                    }
                } else {
                    break 'l1;
                }
            }
        }
    }

    async fn create_message_part_confirmation_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        message_part_confirmation_receiver: async_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        'l1: while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv().await {
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
                    let _ = server.clients_to_disconnect_sender.try_send((
                        addr,
                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                    ));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }

    async fn create_shared_socket_bytes_send_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        shared_socket_bytes_send_receiver: async_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        'l1: while let Ok(bytes) = shared_socket_bytes_send_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if server.socket.send_to(&bytes, addr).await.is_err() {
                    let _ = server.clients_to_disconnect_sender.try_send((
                        addr,
                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                    ));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }
}

/// Properties of the server.
///
/// Intended to be used inside [`Server`].
struct ServerInternal {
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: async_channel::Sender<JoinHandle<()>>,
    /// Sender for signaling the reading of [`Server::ignored_addrs_asking_reason`]
    ignored_addrs_asking_reason_read_signal_sender: async_channel::Sender<()>,
    /// Sender for signaling the reading of [`Server::rejections_to_confirm`]
    rejections_to_confirm_signal_sender: async_channel::Sender<()>,
    /// Sender for addresses to be authenticated.
    clients_to_auth_sender: async_channel::Sender<(SocketAddr, AddrToAuth)>,
    /// Sender for addresses to be disconnected.
    clients_to_disconnect_sender: async_channel::Sender<(
        SocketAddr,
        (ClientDisconnectReason, Option<JustifiedRejectionContext>),
    )>,
    /// Sender for resending pending rejection confirmations.
    pending_rejection_confirm_resend_sender: async_channel::Sender<SocketAddr>,
    /// Sender for resending authentication bytes, like the server public key.
    pending_auth_resend_sender: async_channel::Sender<SocketAddr>,

    /// Receiver for addresses to be authenticated.
    clients_to_auth_receiver: async_channel::Receiver<(SocketAddr, AddrToAuth)>,

    /// Receiver for addresses to be disconnected.
    clients_to_disconnect_receiver: async_channel::Receiver<(
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
    /// Map of addresses asking for the reason they are ignored.
    ignored_addrs_asking_reason: DashMap<IpAddr, SocketAddr>,
    /// Set of addresses asking for the rejection confirm.
    rejections_to_confirm: DashSet<SocketAddr>,

    /// Set of addresses in the authentication process.
    addrs_in_auth: DashSet<SocketAddr>,
    /// Lock-protected set of assigned addresses in authentication.
    assigned_addrs_in_auth: RwLock<HashSet<SocketAddr>>,
    /// Map of pending authentication addresses.
    pending_auth: DashMap<SocketAddr, AddrPendingAuthSend>,

    /// Map of pending rejection confirmations.
    pending_rejection_confirm: DashMap<SocketAddr, JustifiedRejectionContext>,
}

impl ServerInternal {
    fn ignore_ip(&self, ip: IpAddr, reason: IgnoredAddrReason) {
        self.temporary_ignored_ips.remove(&ip);
        self.ignored_ips.insert(ip, reason);
    }

    fn ignore_ip_temporary(
        &self,
        ip: IpAddr,
        reason: IgnoredAddrReason,
        until_to: Instant,
    ) {
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
        let _ = self
            .tasks_keeper_sender
            .try_send(Arc::clone(&self.runtime).spawn(future));
    }

    fn create_async_tasks_keeper(
        runtime: Arc<Runtime>,
        tasks_keeper_receiver: async_channel::Receiver<tokio::task::JoinHandle<()>>,
    ) -> JoinHandle<()> {
        runtime.spawn(async move {
            while let Ok(handle) = tasks_keeper_receiver.recv().await {
                handle.await.unwrap();
            }
        })
    }

    async fn create_pending_auth_resend_handler(
        server: Weak<ServerInternal>,
        pending_auth_resend_receiver: async_channel::Receiver<SocketAddr>,
    ) {
        'l1: while let Ok(addr) = pending_auth_resend_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Some(mut context) = server.pending_auth.get_mut(&addr) {
                    context.last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            } else {
                break 'l1;
            }
        }
    }

    async fn create_pending_rejection_confirm_resend_handler(
        server: Weak<ServerInternal>,
        pending_rejection_confirm_resend_receiver: async_channel::Receiver<SocketAddr>,
    ) {
        'l1: while let Ok(addr) = pending_rejection_confirm_resend_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Some(mut context) = server.pending_rejection_confirm.get_mut(&addr) {
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
        ignored_addrs_asking_reason_read_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = ignored_addrs_asking_reason_read_signal_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                for addr in server.ignored_addrs_asking_reason.iter() {
                    let ip = addr.key();
                    if let Some(reason) = server.ignored_ips.get(&ip) {
                        if let Some(finished_bytes) = &reason.finished_bytes {
                            let _ = server.socket.send_to(&finished_bytes, addr.clone()).await;
                        }
                    }
                }
                server.ignored_addrs_asking_reason.clear();
            } else {
                break 'l1;
            }
        }
    }

    async fn create_rejections_to_confirm_handler(
        server: Weak<ServerInternal>,
        rejections_to_confirm_read_signal_receiver: async_channel::Receiver<()>,
    ) {
        let bytes = &vec![MessageChannel::REJECTION_CONFIRM];
        'l1: while let Ok(_) = rejections_to_confirm_read_signal_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                for addr in server.rejections_to_confirm.iter() {
                    let _ = server.socket.send_to(bytes, addr.clone()).await;
                }
                server.rejections_to_confirm.clear();
            } else {
                break 'l1;
            }
        }
    }

    fn try_check_read_handler(self: &Arc<Self>) {
        if let Ok(mut active_count) = self.read_handler_properties.active_count.try_write() {
            if *active_count < self.read_handler_properties.target_surplus_size - 1 {
                *active_count += 1;
                let downgraded_server = Arc::downgrade(&self);
                self.create_async_task(async move {
                    ServerInternal::create_read_handler(downgraded_server).await;
                });
            }
        }
    }

    async fn create_read_handler(weak_server: Weak<ServerInternal>) {
        let mut was_used = false;
        'l1: loop {
            if let Some(server) = weak_server.upgrade() {
                if *server.read_handler_properties.active_count.write().unwrap()
                    > server.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        server.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break 'l1;
                } else {
                    let read_timeout = server.read_handler_properties.timeout;
                    let socket = Arc::clone(&server.socket);
                    drop(server);

                    let pre_read_next_bytes_result =
                        ServerInternal::pre_read_next_bytes(&socket, read_timeout).await;

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
                    } else {
                        break 'l1;
                    }
                }
            } else {
                break 'l1;
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
        let ip = match addr {
            SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        };
        if bytes.len() < MESSAGE_CHANNEL_SIZE {
            ReadClientBytesResult::InsufficientBytesLen
        } else if self.pending_rejection_confirm.contains_key(&addr) {
            if bytes[0] == MessageChannel::REJECTION_CONFIRM {
                self.pending_rejection_confirm.remove(&addr);
                ReadClientBytesResult::DoneDisconnectConfirm
            } else {
                ReadClientBytesResult::PendingDisconnectConfirm
            }
        } else if let Some(reason) = self.ignored_ips.get(&ip) {
            if reason.finished_bytes.is_some()
                && self.ignored_addrs_asking_reason.len()
                    < self.server_properties.max_ignored_addrs_asking_reason
            {
                self.ignored_addrs_asking_reason.insert(ip, addr);
            }
            ReadClientBytesResult::IgnoredClientHandle
        } else if let Some(client) = self.connected_clients.get(&addr) {
            let mut messaging = client.messaging.lock().await;
            // 8 for UDP header, 40 for IP header (20 for ipv4 or 40 for ipv6)
            messaging.tick_bytes_len += bytes.len() + 8 + 20;
            if messaging.tick_bytes_len > self.messaging_properties.max_client_tick_bytes_len {
                ReadClientBytesResult::ClientMaxTickByteLenOverflow
            } else {
                let _ = client.receiving_bytes_sender.try_send(bytes);
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
                            let _ = self.clients_to_auth_sender.try_send((
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
                        self.ignore_ip_temporary(
                            ip,
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
    

/// Connected server.
pub struct Server {
    internal: Arc<ServerInternal>
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

        let (tasks_keeper_sender, tasks_keeper_receiver) = async_channel::unbounded();
        let (pending_auth_resend_sender, pending_auth_resend_receiver) =
            async_channel::unbounded();
        let (pending_rejection_confirm_resend_sender, pending_rejection_confirm_resend_receiver) =
            async_channel::unbounded();
            let (
                ignored_addrs_asking_reason_read_signal_sender,
                ignored_addrs_asking_reason_read_signal_receiver,
            ) = async_channel::unbounded();
            let (
                rejections_to_confirm_signal_sender,
                rejections_to_confirm_signal_receiver,
            ) = async_channel::unbounded();
                
        let (clients_to_auth_sender, clients_to_auth_receiver) = async_channel::unbounded();
        let (clients_to_disconnect_sender, clients_to_disconnect_receiver) =
            async_channel::unbounded();

        let runtime_clone = Arc::clone(&runtime);

        let server = Arc::new(ServerInternal {
            tasks_keeper_sender,
            ignored_addrs_asking_reason_read_signal_sender,
            rejections_to_confirm_signal_sender,
            clients_to_auth_sender,
            clients_to_disconnect_sender,
            pending_rejection_confirm_resend_sender,
            pending_auth_resend_sender,

            clients_to_auth_receiver,
            clients_to_disconnect_receiver,

            tasks_keeper_handle: ServerInternal::create_async_tasks_keeper(
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
            ignored_ips: DashMap::new(),
            temporary_ignored_ips: DashMap::new(),
            ignored_addrs_asking_reason: DashMap::new(),
            rejections_to_confirm: DashSet::new(),
            addrs_in_auth: DashSet::new(),
            assigned_addrs_in_auth: RwLock::new(HashSet::new()),
            pending_auth: DashMap::new(),
            pending_rejection_confirm: DashMap::new(),
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            ServerInternal::create_pending_auth_resend_handler(
                server_downgraded,
                pending_auth_resend_receiver,
            )
            .await;
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            ServerInternal::create_pending_rejection_confirm_resend_handler(
                server_downgraded,
                pending_rejection_confirm_resend_receiver,
            )
            .await;
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            ServerInternal::create_ignored_addrs_asking_reason_handler(
                server_downgraded,
                ignored_addrs_asking_reason_read_signal_receiver,
            )
            .await;
        });

        let server_downgraded = Arc::downgrade(&server);
        server.create_async_task(async move {
            ServerInternal::create_rejections_to_confirm_handler(
                server_downgraded,
                rejections_to_confirm_signal_receiver,
            )
            .await;
        });

        Ok(BindResult { server:Server{internal:server} })
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
        for addr in dispatched_assigned_addrs_in_auth {
            internal.addrs_in_auth.remove(&addr).unwrap();
        }

        internal.pending_auth.retain(|_, pending_auth_send| {
            now - pending_auth_send.received_time < internal.messaging_properties.timeout_interpretation
        });
        for context in internal.pending_auth.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time
                    < internal
                        .server_properties
                        .pending_auth_packet_loss_interpretation
                {
                    continue;
                }
            }
            internal.pending_auth_resend_sender
                .try_send(context.key().clone())
                .unwrap();
        }

        internal.temporary_ignored_ips.retain(|addr, until_to| {
            if now < *until_to {
                true
            } else {
                internal.ignored_ips.remove(addr);
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
            if let Ok(mut messaging) = client.messaging.try_lock() {
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
                    messaging
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
                < internal.messaging_properties.disconnect_reason_resend_cancel
        });
        for context in internal.pending_rejection_confirm.iter() {
            if let Some(last_sent_time) = context.last_sent_time {
                if now - last_sent_time < internal.messaging_properties.disconnect_reason_resend_delay {
                    continue;
                }
            }
            internal.pending_rejection_confirm_resend_sender
                .try_send(context.key().clone())
                .unwrap();
        }

        for (addr, (reason, context)) in addrs_to_disconnect {
            internal.connected_clients.remove(&addr).unwrap();
            if let Some(context) = context {
                internal.pending_rejection_confirm.insert(addr.clone(), context);
            }
            disconnected.insert(addr, reason);
        }

        for addr in to_auth.keys() {
            assigned_addrs_in_auth.insert(addr.clone());
        }

        internal.ignored_addrs_asking_reason_read_signal_sender
            .try_send(()).unwrap();
        internal.rejections_to_confirm_signal_sender
            .try_send(()).unwrap();

        internal.try_check_read_handler();

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

        let tick_packet_serialized = internal
            .packet_registry
            .serialize(&ServerTickEndPacket)
            .unwrap();

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
        } else if !internal.assigned_addrs_in_auth.write().unwrap().remove(&addr) {
            panic!("Addr was not marked to be authenticated in the last server tick.",)
        } else {
            internal.addrs_in_auth.remove(&addr).unwrap();

            let (receiving_bytes_sender, receiving_bytes_receiver) = async_channel::unbounded();
            let (packets_to_send_sender, packets_to_send_receiver) = async_channel::unbounded();
            let (message_part_confirmation_sender, message_part_confirmation_receiver) =
                async_channel::unbounded();
            let (shared_socket_bytes_send_sender, shared_socket_bytes_send_receiver) =
                async_channel::unbounded();

            let now = Instant::now();

            let messaging = Mutex::new(ConnectedClientMessaging {
                message_part_confirmation_sender,
                shared_socket_bytes_send_sender,
                cipher: ChaChaPoly1305::new(Key::from_slice(addr_to_auth.shared_key.as_bytes())),
                pending_confirmation: BTreeMap::new(),
                incoming_message: MessagePartMap::new(
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
                addr,
                messaging,
                last_messaging_write: RwLock::new(now),
                average_latency: RwLock::new(internal.messaging_properties.initial_latency),
                receiving_bytes_sender,
                packets_to_send_sender,
            });

            let server_downgraded = Arc::downgrade(&internal);
            let client_downgraded = Arc::downgrade(&client);
            internal.create_async_task(async move {
                ConnectedClient::create_receiving_bytes_handler(
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
                ConnectedClient::create_packets_to_send_handler(
                    server_downgraded,
                    client_downgraded,
                    packets_to_send_receiver,
                    initial_next_message_part_id,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&internal);
            internal.create_async_task(async move {
                ConnectedClient::create_message_part_confirmation_handler(
                    server_downgraded,
                    addr,
                    message_part_confirmation_receiver,
                )
                .await;
            });

            let server_downgraded = Arc::downgrade(&internal);
            internal.create_async_task(async move {
                ConnectedClient::create_shared_socket_bytes_send_handler(
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
    pub fn refuse(
        &self,
        addr: SocketAddr,
        _addr_to_auth: AddrToAuth,
        message: SerializedPacketList,
    ) {
        let internal = &self.internal;
        if internal.connected_clients.contains_key(&addr) {
            panic!("Addr is already connected.",)
        } else if !internal.assigned_addrs_in_auth.write().unwrap().remove(&addr) {
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
    pub fn disconnect_from(
        &self,
        client: &ConnectedClient,
        message: Option<SerializedPacketList>,
    ) {
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
        internal.clients_to_disconnect_sender
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
    pub fn ignore_ip_temporary(
        &self,
        ip: IpAddr,
        reason: IgnoredAddrReason,
        until_to: Instant,
    ) {
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
    /// Iterator with the clients connected to the server.
    pub fn connected_clients_iter(
        &self,
    ) -> dashmap::iter::Iter<SocketAddr, Arc<ConnectedClient>> {
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
    /// let server: Arc<Server> = ...;
    /// let addr: SocketAddr = ...;
    /// let client = server.get_connected_client(&addr).unwrap();
    /// let packet = FooPacket {
    ///     message: "Hey ya!".to_owned(),
    /// };
    /// server.send_packet(&client, &packet);
    /// ```
    pub fn send_packet<P: Packet>(&self, client: &ConnectedClient, packet: &P) {
        let internal = &self.internal;
        let serialized = internal
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
            .try_send(Some(packet_serialized))
            .unwrap();
    }

    /// TODO:
    pub fn disconnect_detached(self) {
        todo!();
    }
}