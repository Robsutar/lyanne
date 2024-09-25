use std::{
    collections::BTreeMap,
    fmt::Debug,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use crate::{
    internal::{
        auth::InnerAuth,
        messages::{DeserializedMessage, MessageId, MessagePartId, MessagePartMap},
        rt::{try_read, AsyncRwLock, Mutex, TaskHandle, TaskRunner, UdpSocket},
        utils::{DurationMonitor, RttCalculator},
    },
    packets::{PacketRegistry, SerializedPacket, SerializedPacketList},
    MessagingProperties, ReadHandlerProperties, SentMessagePart,
};

use super::{
    messages::{MessagePart, MessagePartMapTryInsertResult, MessagePartMapTryReadResult},
    MessageChannel,
};

#[cfg(feature = "store_unexpected")]
pub struct StoreUnexpectedErrors<T: std::fmt::Debug> {
    pub error_sender: async_channel::Sender<T>,
    pub error_receiver: async_channel::Receiver<T>,
    pub error_list_sender: async_channel::Sender<Vec<T>>,
    pub error_list_receiver: async_channel::Receiver<Vec<T>>,

    pub create_list_signal_sender: async_channel::Sender<()>,
}

#[cfg(feature = "store_unexpected")]
impl<T: std::fmt::Debug> StoreUnexpectedErrors<T> {
    pub fn new() -> (StoreUnexpectedErrors<T>, async_channel::Receiver<()>) {
        let (error_sender, error_receiver) = async_channel::unbounded();
        let (error_list_sender, error_list_receiver) = async_channel::unbounded();
        let (create_list_signal_sender, create_list_signal_receiver) = async_channel::unbounded();

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
    }
}

pub struct NodeInactiveState<T> {
    pub received_bytes_sender: async_channel::Sender<T>,
}

pub enum NodeState<T> {
    Active,
    Inactive(NodeInactiveState<T>),
}

impl<T> NodeState<T> {
    /// Returns
    /// `true` if the lock of `state` could not be acquired
    /// `true` if the state read value is [`NodeState::Inactive`]
    pub fn is_inactive(state: &AsyncRwLock<NodeState<T>>) -> bool {
        let state = match try_read(state) {
            Some(state) => state,
            None => return true,
        };
        matches!(*state, NodeState::Inactive(_))
    }

    pub async fn set_inactive(
        state: &AsyncRwLock<NodeState<T>>,
        received_bytes_sender: async_channel::Sender<T>,
    ) {
        let mut state = state.write().await;
        *state = NodeState::Inactive(NodeInactiveState {
            received_bytes_sender,
        });
    }
}

pub enum ReceivedBytesProcessResult {
    InvalidProtocolCommunication,
    #[allow(dead_code)]
    AuthMessage(Vec<u8>),
    RejectionJustification(DeserializedMessage),
    MessagePartConfirm,
    MessagePartSent,
}

pub trait NodeType: Send + Sync + Sized + 'static {
    type Skt: Send + Sync + Sized + 'static;
    #[cfg(feature = "store_unexpected")]
    type UnEr: Send + Sync + Sized + 'static + Debug;

    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>>;

    async fn pre_read_next_bytes(socket: &Arc<UdpSocket>) -> io::Result<Self::Skt>;

    async fn pre_read_next_bytes_timeout(
        socket: &Arc<UdpSocket>,
        read_timeout: Duration,
    ) -> io::Result<Self::Skt> {
        let pre_read_next_bytes_result =
            crate::internal::rt::timeout(read_timeout, Self::pre_read_next_bytes(socket)).await;

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

    async fn create_read_handler(weak_node: Weak<NodeInternal<Self>>) {
        let mut was_used = false;
        'l1: loop {
            if let Some(node) = NodeInternal::try_upgrade(&weak_node) {
                if *node.read_handler_properties.active_count.write().unwrap()
                    > node.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        node.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break 'l1;
                } else {
                    let read_timeout = node.messaging_properties.timeout_interpretation;
                    let socket = Arc::clone(&node.socket);
                    drop(node);

                    let pre_read_next_bytes_result =
                        Self::pre_read_next_bytes_timeout(&socket, read_timeout).await;

                    match NodeInternal::try_upgrade_or_get_inactive(&weak_node).await {
                        Some(Ok(node)) => match pre_read_next_bytes_result {
                            Ok(result) => {
                                if !was_used {
                                    was_used = true;
                                    let mut surplus_count =
                                        node.read_handler_properties.active_count.write().unwrap();
                                    *surplus_count -= 1;
                                }

                                Self::consume_read_bytes_result(&node, result).await;
                            }
                            Err(_) => {
                                if was_used {
                                    was_used = false;
                                    let mut surplus_count =
                                        node.read_handler_properties.active_count.write().unwrap();
                                    *surplus_count += 1;
                                }
                            }
                        },
                        Some(Err(inactive_state)) => {
                            if let Ok(result) = pre_read_next_bytes_result {
                                let _ = inactive_state.received_bytes_sender.try_send(result);
                            }
                            break 'l1;
                        }
                        None => {
                            break 'l1;
                        }
                    }
                }
            } else {
                break 'l1;
            }
        }
    }

    async fn consume_read_bytes_result(node: &Arc<NodeInternal<Self>>, result: Self::Skt);

    async fn handle_received_bytes(
        node: &Arc<NodeInternal<Self>>,
        partner: &Partner,
        bytes: Vec<u8>,
    ) -> ReceivedBytesProcessResult {
        let mut messaging = partner.messaging.lock().await;
        match bytes[0] {
            MessageChannel::MESSAGE_PART_CONFIRM => {
                if bytes.len() == 3 {
                    let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                    if let Some((sent_instant, _)) =
                        messaging.pending_confirmation.remove(&message_id)
                    {
                        let delay = Instant::now() - sent_instant;
                        messaging.latency_monitor.push(delay);
                        messaging.average_packet_loss_rtt =
                            messaging.packet_loss_rtt_calculator.update_rtt(
                                &node.messaging_properties.packet_loss_rtt_properties,
                                delay,
                            );
                    }
                    ReceivedBytesProcessResult::MessagePartConfirm
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
                            messaging.average_packet_loss_rtt =
                                messaging.packet_loss_rtt_calculator.update_rtt(
                                    &node.messaging_properties.packet_loss_rtt_properties,
                                    delay,
                                );
                        }
                    }
                    ReceivedBytesProcessResult::MessagePartConfirm
                } else {
                    ReceivedBytesProcessResult::InvalidProtocolCommunication
                }
            }
            MessageChannel::MESSAGE_PART_SEND => {
                let message_part_bytes = partner.inner_auth.extract_after_channel(&bytes);

                let message_part_bytes = match message_part_bytes {
                    Ok(message_part_bytes) => message_part_bytes,
                    Err(_) => {
                        return ReceivedBytesProcessResult::InvalidProtocolCommunication;
                    }
                };

                if let Ok(part) = MessagePart::deserialize(message_part_bytes) {
                    let mut send_fully_message_confirmation = false;
                    let message_id = part.message_id();
                    let part_id = part.id();

                    match messaging.incoming_messages.try_insert(part) {
                        MessagePartMapTryInsertResult::PastMessageId => {
                            let _ = partner
                                .message_part_confirmation_sender
                                .try_send((message_id, None));
                        }
                        MessagePartMapTryInsertResult::Stored => {
                            'l2: loop {
                                match messaging.incoming_messages.try_read(&node.packet_registry){
                                    MessagePartMapTryReadResult::PendingParts => break 'l2,
                                    MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                        return ReceivedBytesProcessResult::InvalidProtocolCommunication;
                                    },
                                    MessagePartMapTryReadResult::SuccessfullyCreated(message) => {
                                        send_fully_message_confirmation = true;

                                        messaging.received_messages.push(message);
                                        messaging.last_received_message_instant = Instant::now();
                                    },
                                }
                            }

                            if send_fully_message_confirmation {
                                let _ = partner
                                    .message_part_confirmation_sender
                                    .try_send((message_id, None));
                            } else {
                                let _ = partner
                                    .message_part_confirmation_sender
                                    .try_send((message_id, Some(part_id)));
                            }
                        }
                    }

                    *partner.incoming_messages_total_size.write().unwrap() =
                        messaging.incoming_messages.total_size();

                    ReceivedBytesProcessResult::MessagePartSent
                } else {
                    ReceivedBytesProcessResult::InvalidProtocolCommunication
                }
            }
            MessageChannel::REJECTION_JUSTIFICATION => {
                let justification_bytes = partner.inner_auth.extract_after_channel(&bytes);

                let justification_bytes = match justification_bytes {
                    Ok(justification_bytes) => justification_bytes,
                    Err(_) => {
                        return ReceivedBytesProcessResult::InvalidProtocolCommunication;
                    }
                };

                if let Ok(message) = DeserializedMessage::deserialize_single_list(
                    &justification_bytes,
                    &node.packet_registry,
                ) {
                    ReceivedBytesProcessResult::RejectionJustification(message)
                } else {
                    ReceivedBytesProcessResult::InvalidProtocolCommunication
                }
            }
            MessageChannel::AUTH_MESSAGE => ReceivedBytesProcessResult::AuthMessage(bytes),
            _ => ReceivedBytesProcessResult::InvalidProtocolCommunication,
        }
    }

    fn push_completed_message_tick(
        node: &NodeInternal<Self>,
        partner: &Partner,
        messaging: &mut PartnerMessaging,
        shared_socket_bytes_send_sender: &async_channel::Sender<Arc<Vec<u8>>>,
        message_id: MessageId,
        serialized_packet_list: SerializedPacketList,
    ) {
        let bytes = serialized_packet_list.bytes;

        let message_parts =
            MessagePart::create_list(&node.messaging_properties, message_id, bytes).unwrap();

        let sent_instant = Instant::now();

        for part in message_parts {
            let part_id = part.id();
            let part_message_id = part.message_id();

            let sent_part = partner.inner_auth.sent_part_of(sent_instant, part);

            let finished_bytes = Arc::clone(&sent_part.finished_bytes);

            let (_, pending_part_id_map) = messaging
                .pending_confirmation
                .entry(part_message_id)
                .or_insert_with(|| (sent_instant, BTreeMap::new()));
            pending_part_id_map.insert(part_id, sent_part);

            let _ = shared_socket_bytes_send_sender.try_send(finished_bytes);
        }
    }

    #[cfg(feature = "store_unexpected")]
    async fn store_unexpected_error_list_pick(node: &NodeInternal<Self>) -> Vec<Self::UnEr> {
        let mut list = Vec::<Self::UnEr>::new();
        while let Ok(mut error_list) = node.store_unexpected_errors.error_list_receiver.try_recv() {
            list.append(&mut error_list);
        }
        while let Ok(error) = node.store_unexpected_errors.error_receiver.try_recv() {
            list.push(error);
        }

        list
    }
}
pub struct PartnerMessaging {
    /// Map of message parts pending confirmation.
    /// The tuple is the sent instant, and the map of the message parts of the message.
    pub pending_confirmation:
        BTreeMap<MessageId, (Instant, BTreeMap<MessagePartId, SentMessagePart>)>,

    /// Map of incoming messages parts.
    pub incoming_messages: MessagePartMap,
    /// The length of bytes received in the current tick.
    pub tick_bytes_len: usize,

    /// The instant when the last message was received.
    pub last_received_message_instant: Instant,
    /// The deserialized messages that have been received and have not been read yet.
    pub received_messages: Vec<DeserializedMessage>,

    /// Calculator for packet loss round-trip time.
    pub packet_loss_rtt_calculator: RttCalculator,
    /// The average round-trip time for packet loss.
    pub average_packet_loss_rtt: Duration,
    /// Monitor for latency duration.
    pub latency_monitor: DurationMonitor,
}

/// Properties of a partner that is connected to the node.
pub struct Partner {
    /// Sender for receiving bytes.
    pub(crate) receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    /// Sender for packets to be sent.
    pub(crate) packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,
    /// Sender for message part confirmations.
    pub(crate) message_part_confirmation_sender:
        async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    pub(crate) shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

    /// The socket address of the connected partner.
    pub(crate) addr: SocketAddr,
    /// Authenticator bound to this partner.
    pub(crate) inner_auth: InnerAuth,

    /// Messaging-related properties wrapped in an [`Mutex`].
    pub(crate) messaging: Mutex<PartnerMessaging>,
    /// The last instant when a messaging write operation occurred.
    pub(crate) last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    pub(crate) average_latency: RwLock<Duration>,
    /// The byte size of [`PartnerMessaging::incoming_messages`]
    pub(crate) incoming_messages_total_size: RwLock<usize>,
}

impl Partner {
    /// # Returns
    /// The average time of messaging response of this partner after a node message.
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }

    /// # Returns
    /// The total size of the stored incoming messages, that were not completed wet, or not read yet.
    pub fn incoming_messages_total_size(&self) -> usize {
        *self.incoming_messages_total_size.read().unwrap()
    }
}

/// Properties of the node.
pub struct NodeInternal<T: NodeType> {
    /// Sender for make the spawned tasks keep alive.
    pub tasks_keeper_sender: async_channel::Sender<TaskHandle<()>>,

    /// Task handle of the receiver.
    pub tasks_keeper_handle: Mutex<Option<TaskHandle<()>>>,

    /// The UDP socket used for communication.
    pub socket: Arc<UdpSocket>,

    #[cfg(feature = "store_unexpected")]
    /// List of errors emitted in the tick.
    pub store_unexpected_errors: StoreUnexpectedErrors<T::UnEr>,

    /// The registry for packets.
    pub packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    pub messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    pub read_handler_properties: Arc<ReadHandlerProperties>,

    pub task_runner: Arc<TaskRunner>,

    pub node_type: T,
}

impl<T: NodeType> NodeInternal<T> {
    pub fn try_upgrade(downgraded: &Weak<Self>) -> Option<Arc<Self>> {
        if let Some(internal) = downgraded.upgrade() {
            if NodeState::is_inactive(&internal.node_type.state()) {
                None
            } else {
                Some(internal)
            }
        } else {
            None
        }
    }

    pub async fn try_upgrade_or_get_inactive(
        downgraded: &Weak<Self>,
    ) -> Option<Result<Arc<Self>, NodeInactiveState<T::Skt>>> {
        if let Some(internal) = downgraded.upgrade() {
            let inactive_ref = match &*internal.node_type.state().read().await {
                NodeState::Active => None,
                NodeState::Inactive(inactive_state) => Some(NodeInactiveState {
                    received_bytes_sender: inactive_state.received_bytes_sender.clone(),
                }),
            };

            match inactive_ref {
                Some(inactive_state) => Some(Err(inactive_state)),
                None => Some(Ok(internal)),
            }
        } else {
            None
        }
    }

    pub fn create_async_task<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let _ = self
            .tasks_keeper_sender
            .try_send(self.task_runner.spawn(future));
    }

    pub fn on_holder_drop(self: &Arc<Self>) {
        if !NodeState::is_inactive(&self.node_type.state()) {
            let (received_bytes_sender, received_bytes_receiver) = async_channel::unbounded();

            let internal = Arc::clone(&self);
            let _ = self.create_async_task(async move {
                NodeState::set_inactive(&internal.node_type.state(), received_bytes_sender).await;
            });

            drop(received_bytes_receiver);
        }
    }
}
