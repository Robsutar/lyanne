use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use crate::{
    internal::{
        auth::InnerAuth,
        messages::{DeserializedMessage, MessageId, MessagePartId, MessagePartMap},
        rt::{select, try_read, AsyncRwLock, Mutex, TaskHandle, TaskRunner, UdpSocket},
        utils::{DurationMonitor, RttCalculator},
    },
    packets::{PacketRegistry, SerializedPacket, SerializedPacketList},
    MessagingProperties, ReadHandlerProperties, SentMessagePart,
};

use super::{
    messages::{MessagePart, MessagePartMapTryInsertResult, MessagePartMapTryReadResult},
    rt::SelectArm,
    MessageChannel,
};

#[cfg(feature = "store_unexpected")]
use std::fmt::Debug;

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

pub struct ActiveDisposableHandler {
    pub task: TaskHandle<()>,
}
impl ActiveDisposableHandler {
    async fn dispose(task_runner: &TaskRunner, disposable_handlers_keeper: &Mutex<Vec<Self>>) {
        let mut disposable_handlers_keeper = disposable_handlers_keeper.lock().await;
        while !disposable_handlers_keeper.is_empty() {
            let active = disposable_handlers_keeper.remove(0);
            let _ = task_runner.cancel(active.task).await;
        }
    }
}

pub struct ActiveCancelableHandler {
    pub cancel_sender: async_channel::Sender<()>,
    pub task: TaskHandle<()>,
}
impl ActiveCancelableHandler {
    async fn cancel(cancelable_handlers_keeper: &Mutex<Vec<Self>>) {
        let mut cancelable_handlers_keeper = cancelable_handlers_keeper.lock().await;
        while !cancelable_handlers_keeper.is_empty() {
            let active = cancelable_handlers_keeper.remove(0);
            let _ = active.cancel_sender.send(()).await;
            let _ = active.task.await;
        }
    }
}

pub enum NodeState {
    Active,
    Inactive,
}

impl NodeState {
    /// Returns
    /// `true` if the lock of `state` could not be acquired
    /// `true` if the state read value is [`NodeState::Inactive`]
    pub fn is_inactive(state: &AsyncRwLock<NodeState>) -> bool {
        let state = match try_read(state) {
            Some(state) => state,
            None => return true,
        };
        matches!(*state, NodeState::Inactive)
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

    async fn create_read_handler(
        weak_node: Weak<NodeInternal<Self>>,
        socket: Arc<UdpSocket>,
        cancel_receiver: async_channel::Receiver<()>,
    ) {
        'l1: loop {
            let pre_read_next_bytes_result =
                match select(Self::pre_read_next_bytes(&socket), cancel_receiver.recv()).await {
                    SelectArm::Left(pre_read_next_bytes_result) => pre_read_next_bytes_result,
                    SelectArm::Right(_) => {
                        break 'l1;
                    }
                };

            if let Some(node) = NodeInternal::try_upgrade(&weak_node) {
                match pre_read_next_bytes_result {
                    Ok(result) => {
                        Self::consume_read_bytes_result(&node, result).await;
                    }
                    Err(_) => {}
                };
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
    pub(crate) disposable_handlers_keeper: Mutex<Vec<ActiveDisposableHandler>>,

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
    /// The address of the partner
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

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
    pub disposable_handlers_keeper: Mutex<Vec<ActiveDisposableHandler>>,
    pub cancelable_handlers_keeper: Mutex<Vec<ActiveCancelableHandler>>,

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

    pub state: AsyncRwLock<NodeState>,
    pub node_type: T,
}

impl<T: NodeType> NodeInternal<T> {
    pub fn try_upgrade(downgraded: &Weak<Self>) -> Option<Arc<Self>> {
        if let Some(internal) = downgraded.upgrade() {
            if NodeState::is_inactive(&internal.state) {
                None
            } else {
                Some(internal)
            }
        } else {
            None
        }
    }

    pub async fn set_state_inactive(node: &Arc<Self>) {
        {
            let mut state = node.state.write().await;
            *state = NodeState::Inactive;
        }
        ActiveCancelableHandler::cancel(&node.cancelable_handlers_keeper).await;
        ActiveDisposableHandler::dispose(&node.task_runner, &node.disposable_handlers_keeper).await;
    }

    pub async fn on_partner_disposed(node: &Arc<Self>, partner: &Partner) {
        ActiveDisposableHandler::dispose(&node.task_runner, &partner.disposable_handlers_keeper)
            .await;
    }

    pub fn on_holder_drop(self: &Arc<Self>) {
        if !NodeState::is_inactive(&self.state) {
            let internal = Arc::clone(&self);
            let _ = self.create_async_task(async move {
                Self::set_state_inactive(&internal).await;
            });
        }
    }
}
