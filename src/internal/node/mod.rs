mod init;

use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    internal::{
        auth::InnerAuth,
        messages::{
            DeserializedMessage, MessageId, MessagePartId, MessagePartMap, PUBLIC_KEY_SIZE,
            UDP_BUFFER_SIZE,
        },
        rt::{try_lock, try_read, AsyncRwLock, Mutex, TaskHandle, TaskRunner, UdpSocket},
        utils::{DurationMonitor, RttCalculator},
        MessageChannel,
    },
    packets::{ClientTickEndPacket, Packet, PacketRegistry, SerializedPacket},
    LimitedMessage, MessagingProperties, ReadHandlerProperties, SentMessagePart,
    MESSAGE_CHANNEL_SIZE,
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

pub trait NodeType {
    type Skt;
    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>>;
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
    pub receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    /// Sender for packets to be sent.
    pub packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,
    /// Sender for message part confirmations.
    pub message_part_confirmation_sender: async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    pub shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

    /// The socket address of the connected partner.
    pub addr: SocketAddr,
    /// Authenticator bound to this partner.
    pub inner_auth: InnerAuth,

    /// Messaging-related properties wrapped in an [`Mutex`].
    pub messaging: Mutex<PartnerMessaging>,
    /// The last instant when a messaging write operation occurred.
    pub last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    pub average_latency: RwLock<Duration>,
    /// The byte size of [`PartnerMessaging::incoming_messages`]
    pub incoming_messages_total_size: RwLock<usize>,
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
                NodeState::Inactive(server_inactive_state) => Some(NodeInactiveState {
                    received_bytes_sender: server_inactive_state.received_bytes_sender.clone(),
                }),
            };

            match inactive_ref {
                Some(server_inactive_state) => Some(Err(server_inactive_state)),
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
}
