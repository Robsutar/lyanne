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

#[cfg(feature = "store_unexpected")]
struct StoreUnexpectedErrors {
    error_sender: async_channel::Sender<UnexpectedError>,
    error_receiver: async_channel::Receiver<UnexpectedError>,
    error_list_sender: async_channel::Sender<Vec<UnexpectedError>>,
    error_list_receiver: async_channel::Receiver<Vec<UnexpectedError>>,

    create_list_signal_sender: async_channel::Sender<()>,
}

#[cfg(feature = "store_unexpected")]
impl StoreUnexpectedErrors {
    pub fn new() -> (StoreUnexpectedErrors, async_channel::Receiver<()>) {
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

struct NodeInactiveState<T> {
    received_bytes_sender: async_channel::Sender<T>,
}

enum NodeState<T> {
    Active,
    Inactive(NodeInactiveState<T>),
}

impl<T> NodeState<T> {
    /// Returns
    /// `true` if the lock of `state` could not be acquired
    /// `true` if the state read value is [`NodeState::Inactive`]
    fn is_inactive(state: &AsyncRwLock<NodeState<T>>) -> bool {
        let state = match try_read(state) {
            Some(state) => state,
            None => return true,
        };
        matches!(*state, NodeState::Inactive(_))
    }

    async fn set_inactive(
        state: &AsyncRwLock<NodeState<T>>,
        received_bytes_sender: async_channel::Sender<T>,
    ) {
        let mut state = state.write().await;
        *state = NodeState::Inactive(NodeInactiveState {
            received_bytes_sender,
        });
    }
}

trait NodeType {
    type Skt;
    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>>;
}

struct ClientNode {
    state: AsyncRwLock<NodeState<Vec<u8>>>,
}

impl NodeType for ClientNode {
    type Skt = (SocketAddr, Vec<u8>);

    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>> {
        self.state
    }
}

struct ServerNode {
    state: AsyncRwLock<NodeState<(SocketAddr, Vec<u8>)>>,
}

impl NodeType for ServerNode {
    type Skt = Vec<u8>;

    fn state(&self) -> &AsyncRwLock<NodeState<Self::Skt>> {
        self.state
    }
}

pub struct PartnerMessaging {
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

/// Properties of a partner that is connected to the node.
pub struct Partner {
    /// Sender for receiving bytes.
    receiving_bytes_sender: async_channel::Sender<Vec<u8>>,
    /// Sender for packets to be sent.
    packets_to_send_sender: async_channel::Sender<Option<SerializedPacket>>,
    /// Sender for message part confirmations.
    message_part_confirmation_sender: async_channel::Sender<(MessageId, Option<MessagePartId>)>,
    /// Sender for shared socket bytes.
    shared_socket_bytes_send_sender: async_channel::Sender<Arc<Vec<u8>>>,

    /// The socket address of the connected partner.
    addr: SocketAddr,
    /// Authenticator bound to this partner.
    inner_auth: InnerAuth,

    /// Messaging-related properties wrapped in an [`Mutex`].
    messaging: Mutex<PartnerMessaging>,
    /// The last instant when a messaging write operation occurred.
    last_messaging_write: RwLock<Instant>,
    /// The average latency duration.
    average_latency: RwLock<Duration>,
    /// The byte size of [`PartnerMessaging::incoming_messages`]
    incoming_messages_total_size: RwLock<usize>,
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
struct NodeInternal<T: NodeType> {
    /// Sender for make the spawned tasks keep alive.
    tasks_keeper_sender: async_channel::Sender<TaskHandle<()>>,

    #[cfg(feature = "store_unexpected")]
    /// List of errors emitted in the tick.
    store_unexpected_errors: StoreUnexpectedErrors,

    /// The UDP socket used for communication.
    socket: Arc<UdpSocket>,

    /// Task handle of the receiver.
    tasks_keeper_handle: Mutex<Option<TaskHandle<()>>>,

    /// The registry for packets.
    packet_registry: Arc<PacketRegistry>,
    /// Properties related to messaging.
    messaging_properties: Arc<MessagingProperties>,
    /// Properties related to read handlers.
    read_handler_properties: Arc<ReadHandlerProperties>,

    task_runner: Arc<TaskRunner>,

    node_type: T,
}

impl<T: NodeType> NodeInternal<T> {
    fn try_upgrade(downgraded: &Weak<Self>) -> Option<Arc<Self>> {
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

    async fn try_upgrade_or_get_inactive(
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

    fn create_async_task<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let _ = self
            .tasks_keeper_sender
            .try_send(self.task_runner.spawn(future));
    }
}
