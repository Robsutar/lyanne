use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use colored::*;

use dashmap::DashMap;
use tokio::{
    net::UdpSocket,
    runtime::Runtime,
    time::{sleep, timeout},
};

use crate::{
    messages::{
        DeserializedMessage, DeserializedMessageCheck, MessagePart, MessagePartId,
        MessagePartLargeId,
    },
    packets::{
        ConfirmAuthenticationPacket, Packet, PacketRegistry, SerializedPacket,
        SerializedPacketList, ServerTickCalledPacket,
    },
    utils::{self, DurationMonitor},
};

use super::{MessageChannel, MessagingProperties};

#[cfg(feature = "troubles_simulator")]
use super::troubles_simulator::NetTroublesSimulatorProperties;

/// Possible results when receiving bytes by clients
#[derive(Debug)]
pub enum ReadClientBytesResult {
    AuthenticationRequest,
    CompletedMessagePartSend,
    ValidMessagePartSend,
    AlreadyAssignedMessagePartSend,
    ValidMessagePartConfirm,
    AlreadyAssignedMessagePartConfirm,
    #[cfg(feature = "troubles_simulator")]
    PacketLossSimulation,
    ClosedMessageChannel,
    OverflowAuthenticationRequest,
    InvalidAuthenticationRequest(io::Error),
    InvalidChannelEntry,
    InsufficientBytesLen,
    InvalidMessagePart,
    InvalidDeserializedMessage,
    ClientPoisoned,
}

impl ReadClientBytesResult {
    /// Default validation of client sent bytes interpretation result
    /// # Returns
    ///
    /// false if the result is not considered as valid, so, can be interpreted
    /// that the client sent an invalid data, and should be ignored/disconnected
    pub fn is_valid(&self) -> bool {
        match self {
            ReadClientBytesResult::AuthenticationRequest => true,
            ReadClientBytesResult::CompletedMessagePartSend => true,
            ReadClientBytesResult::ValidMessagePartSend => true,
            ReadClientBytesResult::AlreadyAssignedMessagePartSend => true,
            ReadClientBytesResult::ValidMessagePartConfirm => true,
            ReadClientBytesResult::AlreadyAssignedMessagePartConfirm => true,
            #[cfg(feature = "troubles_simulator")]
            ReadClientBytesResult::PacketLossSimulation => true,
            ReadClientBytesResult::ClosedMessageChannel => true,
            ReadClientBytesResult::OverflowAuthenticationRequest => false,
            ReadClientBytesResult::InvalidAuthenticationRequest(_) => false,
            ReadClientBytesResult::InvalidChannelEntry => false,
            ReadClientBytesResult::InsufficientBytesLen => false,
            ReadClientBytesResult::InvalidMessagePart => false,
            ReadClientBytesResult::InvalidDeserializedMessage => false,
            ReadClientBytesResult::ClientPoisoned => false,
        }
    }
}

/// Properties for the client bytes read handlers, used in [`add_read_handler()`]
pub struct ReadHandlerProperties {
    /// Number of asynchronous tasks that must be slacking when receiving packets
    pub surplus_target_size: u16,
    /// Max time to try read [`pre_read_next_bytes()`]
    pub surplus_timeout: Duration,
    /// Actual number of active asynchronous read handlers
    // TODO: use RwLock, and try_write in server tick, to prevent thread spawn
    pub surplus_count: Arc<tokio::sync::Mutex<u16>>,
}

impl Default for ReadHandlerProperties {
    fn default() -> Self {
        ReadHandlerProperties {
            surplus_target_size: 5u16,
            surplus_timeout: Duration::from_secs(15),
            surplus_count: Arc::new(tokio::sync::Mutex::new(0u16)),
        }
    }
}

/// Possible reasons to be disconnected from some client
#[derive(Debug, Clone, Copy)]
pub enum ClientDisconnectReason {
    PendingMessageConfirmationTimeout,
    MessageReceiveTimeout,
    ManualDisconnect,
}

/// Result when calling [`bind()`]
pub struct BindResult {
    pub server: Arc<Server>,
}

/// Result when calling [`tick()`]
pub struct ServerTickResult {
    pub received_messages: Vec<(SocketAddr, DeserializedMessage)>,
    pub clients_to_authenticate: HashMap<SocketAddr, DeserializedMessage>,
    pub clients_disconnected: HashMap<SocketAddr, ClientDisconnectReason>,
}

/// Properties of the server
///
/// Intended to use used with [`Arc`]
pub struct Server {
    // Read
    pub socket: UdpSocket,
    pub runtime: Arc<Runtime>,
    pub packet_registry: Arc<PacketRegistry>,
    pub messaging_properties: Arc<MessagingProperties>,
    pub read_handler_properties: Arc<ReadHandlerProperties>,
    #[cfg(feature = "troubles_simulator")]
    pub net_troubles_simulator: Option<Arc<NetTroublesSimulatorProperties>>,

    // Write
    pub connected_clients: DashMap<SocketAddr, ConnectedClient>,
    clients_to_try_auth: DashMap<SocketAddr, DeserializedMessage>,
    set_connected_sender: crossbeam_channel::Sender<SocketAddr>,
    set_connected_receiver: crossbeam_channel::Receiver<SocketAddr>,
}

impl Server {
    /// Mark a client to be connected in the next tick
    pub fn connect(&self, addr: SocketAddr) {
        self.set_connected_sender.send(addr).unwrap();
    }
}

/// Messaging fields of [`ConnectedClient`]
///
/// Intended to be used with [`Arc`] and [`RwLock`]
struct ConnectedClientMessaging {
    next_message_to_receive_start_id: MessagePartId,
    pending_client_confirmation: BTreeMap<MessagePartLargeId, (Instant, MessagePart)>,
    incoming_messages: BTreeMap<MessagePartLargeId, MessagePart>,
    received_message: Option<(Instant, DeserializedMessage)>,
    last_received_message: Instant,
    last_sent_message: Instant,
    latency_monitor: DurationMonitor,
}

/// Mutable and shared between threads properties of the connected client
///
/// Intended to be used inside [`ServerAsync`]
pub struct ConnectedClient {
    messaging: Arc<RwLock<ConnectedClientMessaging>>,
    average_latency: RwLock<Duration>,
    disconnect_sender: crossbeam_channel::Sender<ClientDisconnectReason>,
    disconnect_receiver: crossbeam_channel::Receiver<ClientDisconnectReason>,
    packets_to_send_sender: crossbeam_channel::Sender<Option<SerializedPacket>>,
    message_parts_to_confirm_sender: crossbeam_channel::Sender<MessagePartId>,
    packet_loss_resending_sender: crossbeam_channel::Sender<MessagePartLargeId>,
}

impl ConnectedClient {
    pub fn send<P: Packet>(&self, server: &Server, packet: &P) -> io::Result<()> {
        let serialized = server.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&self, serialized_packet: SerializedPacket) {
        self.packets_to_send_sender
            .send(Some(serialized_packet))
            .unwrap();
    }

    /// Mark the client to be removed from authenticated clients in the next tick
    /// # Returns
    /// false if the client is already marked to be disconnected
    pub fn disconnect(&self) -> bool {
        match self
            .disconnect_sender
            .try_send(ClientDisconnectReason::ManualDisconnect)
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// # Returns
    /// The average time of messaging response of this client after a server message
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }
}

/// Bind a [`UdpSocket´], to create a new Server instance
pub async fn bind(
    addr: SocketAddr,
    packet_registry: Arc<PacketRegistry>,
    messaging_properties: Arc<MessagingProperties>,
    read_handler_properties: Arc<ReadHandlerProperties>,
    #[cfg(feature = "troubles_simulator")] net_troubles_simulator: Option<
        Arc<NetTroublesSimulatorProperties>,
    >,
    runtime: Arc<Runtime>,
) -> io::Result<BindResult> {
    let socket = UdpSocket::bind(addr).await?;

    let (set_connected_sender, set_connected_receiver) = crossbeam_channel::unbounded();

    let server = Arc::new(Server {
        socket,
        runtime,
        packet_registry,
        messaging_properties,
        read_handler_properties,
        #[cfg(feature = "troubles_simulator")]
        net_troubles_simulator,

        connected_clients: DashMap::new(),
        clients_to_try_auth: DashMap::new(),
        set_connected_sender,
        set_connected_receiver,
    });

    for _ in 0..server.read_handler_properties.surplus_target_size {
        add_read_handler(Arc::clone(&server));
    }

    Ok(BindResult { server })
}

/// Server main tick
/// - Handles packet loss
/// - Handles timeout
/// - Send [`packets_to_send`] to the clients
/// - Authenticate the clients [`marked_to_set_authenticated`] and
/// remove authentication of the clients [`marked_to_unset_authenticated`]
///
/// # Returns
/// - Received messages sent by the clients
/// - Received messages sent by clients authentication requests
/// - Clients disconnected
///
pub fn tick(server: Arc<Server>) -> ServerTickResult {
    let now = Instant::now();
    let mut received_messages: Vec<(SocketAddr, DeserializedMessage)> = Vec::new();
    let mut clients_to_disconnect: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

    let mut clients_to_connect: HashSet<SocketAddr> = HashSet::new();
    while let Ok(addr) = server.set_connected_receiver.try_recv() {
        clients_to_connect.insert(addr);
    }

    let mut clients_to_authenticate: HashMap<SocketAddr, DeserializedMessage> = HashMap::new();
    let mut keys_to_remove = Vec::new();

    for entry in server.clients_to_try_auth.iter() {
        keys_to_remove.push(entry.key().clone());
    }

    for key in keys_to_remove {
        if let Some((addr, message)) = server.clients_to_try_auth.remove(&key) {
            clients_to_authenticate.insert(addr, message);
        }
    }

    let tick_packet_serialized = server
        .packet_registry
        .serialize(&ServerTickCalledPacket)
        .unwrap();

    for entry in server.connected_clients.iter() {
        let (addr, client) = (entry.key(), entry.value());
        if let Ok(reason) = client.disconnect_receiver.try_recv() {
            clients_to_disconnect.insert(addr.clone(), reason);
            continue;
        }
        let messaging = client.messaging.read().unwrap();

        if now - messaging.last_received_message
            >= server.messaging_properties.timeout_interpretation
        {
            clients_to_disconnect
                .insert(addr.clone(), ClientDisconnectReason::MessageReceiveTimeout);
            continue;
        }

        let addr = addr.clone();

        client.send_packet_serialized(SerializedPacket::clone(&tick_packet_serialized));
        drop(messaging);
        if let Ok(mut messaging_write) = client.messaging.try_write() {
            if messaging_write.pending_client_confirmation.is_empty() {
                if let Some((time, message)) = messaging_write.received_message.take() {
                    let delay = time - messaging_write.last_sent_message;
                    messaging_write.latency_monitor.push(delay);
                    let average_latency = messaging_write.latency_monitor.average_duration();
                    *client.average_latency.write().unwrap() = average_latency;

                    println!(
                        "{}",
                        format!(
                            "last ping-pong delay: {:?}, average latency: {:?}",
                            delay, average_latency
                        )
                        .bright_black()
                    );
                    messaging_write.last_received_message = time;
                    received_messages.push((addr.clone(), message));

                    client.packets_to_send_sender.send(None).unwrap();
                }
            } else {
                for (large_id, (ref mut instant, _)) in
                    messaging_write.pending_client_confirmation.iter_mut()
                {
                    if now - *instant >= server.messaging_properties.timeout_interpretation {
                        clients_to_disconnect.insert(
                            addr.clone(),
                            ClientDisconnectReason::PendingMessageConfirmationTimeout,
                        );
                        break;
                    }
                    if now - *instant >= server.messaging_properties.packet_loss_interpretation {
                        *instant = now;
                        let _ = client.packet_loss_resending_sender.send(*large_id);
                    }
                }
            }
        } else {
            println!(
                "{}",
                format!(
                    "client {:?}, locked, trying solve the tasks in next tick",
                    addr
                )
                .red()
            )
        }
    }

    let confirm_authentication_serialized = server
        .packet_registry
        .serialize(&ConfirmAuthenticationPacket)
        .unwrap();

    let mut log = String::new();
    for addr in clients_to_connect {
        log.push_str(&format!("trying connect {:?}", addr));
        if !server.connected_clients.contains_key(&addr) {
            log.push_str(&format!("{}", "  connecting"));

            let (packets_to_send_sender, packets_to_send_receiver) = crossbeam_channel::unbounded();
            let (disconnect_sender, disconnect_receiver) = crossbeam_channel::bounded(1);
            let (message_parts_to_confirm_sender, message_parts_to_confirm_receiver) =
                crossbeam_channel::unbounded();
            let (packet_loss_resending_sender, packet_loss_resending_receiver) =
                crossbeam_channel::unbounded();

            let client = ConnectedClient {
                messaging: Arc::new(RwLock::new(ConnectedClientMessaging {
                    next_message_to_receive_start_id: server
                        .messaging_properties
                        .initial_next_message_part_id,
                    pending_client_confirmation: BTreeMap::new(),
                    incoming_messages: BTreeMap::new(),
                    received_message: None,
                    last_received_message: Instant::now(),
                    last_sent_message: Instant::now(),
                    latency_monitor: DurationMonitor::filled_with(Duration::from_millis(50), 10),
                })),
                average_latency: RwLock::new(Duration::from_millis(50)),
                packets_to_send_sender,
                disconnect_sender,
                disconnect_receiver,
                message_parts_to_confirm_sender,
                packet_loss_resending_sender,
            };

            client.send_packet_serialized(SerializedPacket::clone(
                &confirm_authentication_serialized,
            ));
            client.packets_to_send_sender.send(None).unwrap();

            create_client_packet_confirmation_thread(
                Arc::clone(&server),
                addr.clone(),
                message_parts_to_confirm_receiver,
            );

            create_client_packet_sending_thread(
                Arc::clone(&server),
                addr.clone(),
                packets_to_send_receiver,
                Arc::clone(&client.messaging),
            );

            create_client_packet_loss_resending_thread(
                Arc::clone(&server),
                addr.clone(),
                packet_loss_resending_receiver,
                Arc::clone(&client.messaging),
            );

            server.connected_clients.insert(addr.clone(), client);
        }
    }

    let mut clients_disconnected: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

    for (addr, reason) in clients_to_disconnect {
        log.push_str(&format!("trying disconnect {:?} for {:?}", addr, reason));
        server.connected_clients.remove(&addr).unwrap();
        log.push_str(&format!("  done disconnect"));
        clients_disconnected.insert(addr, reason);
    }

    if log.len() > 0 {
        println!("{}", log.red().bold());
    }

    Arc::clone(&server.runtime).spawn(async move {
        if *server.read_handler_properties.surplus_count.lock().await
            < server.read_handler_properties.surplus_target_size - 1
        {
            add_read_handler(Arc::clone(&server));
        }
    });

    ServerTickResult {
        received_messages,
        clients_to_authenticate,
        clients_disconnected,
    }
}

/// Read bytes for some client, just using a reference of ServerRead
pub async fn pre_read_next_bytes(server: &Arc<Server>) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut buf = [0u8; 1024];
    let (len, addr) = server.socket.recv_from(&mut buf).await?;
    Ok((addr, buf[..len].to_vec()))
}

/// Uses bytes read by [`pre_read_next_bytes()`] and process them
///
/// # Returns
///
/// The result of the process of those bytes, if the return is invalid
/// (check it with[`ReadClientBytesResult::is_valid()`]), a ignore or
/// disconnection of that client is recommended
pub async fn read_next_bytes(
    server: &Arc<Server>,
    tuple: (SocketAddr, Vec<u8>),
) -> ReadClientBytesResult {
    println!("{} {:?}", "bytes: ".red(), tuple.1.len());
    let (addr, bytes) = tuple;
    if bytes.len() < 2 {
        return ReadClientBytesResult::InsufficientBytesLen;
    }

    #[cfg(feature = "troubles_simulator")]
    if let Some(net_troubles_simulator) = &server.net_troubles_simulator {
        if net_troubles_simulator.ranged_packet_loss() {
            println!("{}", "packet loss simulation!!!".red());
            return ReadClientBytesResult::PacketLossSimulation;
        } else if let Some(delay) = net_troubles_simulator.ranged_ping_delay() {
            sleep(delay).await;
            println!("{}", format!("delay of {:?} was simulated!!!", delay).red());
        }
    }

    if let Some(client) = server.connected_clients.get(&addr) {
        if let Ok(mut messaging_write) = client.messaging.write() {
            match bytes[0] {
                MessageChannel::MESSAGE_PART_CONFIRM => {
                    let REMOVE_VAR = utils::remove_with_rotation(
                        &mut messaging_write.pending_client_confirmation,
                        bytes[1],
                    );
                    if let Some(_) = REMOVE_VAR {
                        println!(
                            "{}",
                            format!("[MESSAGE_PART_CONFIRM] successfully removed {:?}", bytes[1])
                                .green()
                        );
                        return ReadClientBytesResult::ValidMessagePartConfirm;
                    } else {
                        println!(
                            "{}",
                            format!(
                                "[MESSAGE_PART_CONFIRM] already removed {:?}, possible keys: {:?}",
                                bytes[1],
                                messaging_write.pending_client_confirmation.keys(),
                            )
                            .red()
                        );
                        return ReadClientBytesResult::AlreadyAssignedMessagePartConfirm;
                    }
                }
                MessageChannel::MESSAGE_PART_SEND => {
                    let mut log = String::new();
                    if let Some(_) = messaging_write.received_message {
                        return ReadClientBytesResult::ClosedMessageChannel;
                    }
                    if let Ok(part) = MessagePart::deserialize(bytes[1..].to_vec()) {
                        let next_message_to_receive_start_id =
                            messaging_write.next_message_to_receive_start_id;

                        log.push_str(&format!(
                            "\n{} {:?} {:?}",
                            "part received".purple(),
                            part.id(),
                            next_message_to_receive_start_id
                        ));
                        log.push_str(&format!("\n  {}", "sending confirmation".purple()));
                        let _ = client.message_parts_to_confirm_sender.send(part.id());
                        if Ordering::Less
                            != utils::compare_with_rotation(
                                part.id(),
                                next_message_to_receive_start_id,
                            )
                        {
                            let large_index: MessagePartLargeId = {
                                if part.id() >= next_message_to_receive_start_id {
                                    part.id() as MessagePartLargeId
                                } else {
                                    part.id() as MessagePartLargeId + 256
                                }
                            };

                            messaging_write.incoming_messages.insert(large_index, part);
                            log.push_str(&format!(
                                            "\n     large_index: {:?}, actual incoming_messages size: {:?}, keys: {:?}",
                                            large_index,
                                            messaging_write.incoming_messages.len(),
                                            messaging_write.incoming_messages.keys(),
                                        ).purple());
                            if let Ok(check) =
                                DeserializedMessageCheck::new(&messaging_write.incoming_messages)
                            {
                                let incoming_messages = std::mem::replace(
                                    &mut messaging_write.incoming_messages,
                                    BTreeMap::new(),
                                );
                                let new_next_message_to_receive_start_id =
                                    ((incoming_messages.last_key_value().unwrap().0 + 1) % 256)
                                        as MessagePartId;
                                log.push_str(&format!(
                                    "\n{} {:?}",
                                    "new_next_message_to_receive_start_id: IN".purple(),
                                    new_next_message_to_receive_start_id
                                ));
                                if let Ok(message) = DeserializedMessage::deserialize(
                                    &server.packet_registry,
                                    check,
                                    incoming_messages,
                                ) {
                                    messaging_write.next_message_to_receive_start_id =
                                        new_next_message_to_receive_start_id;

                                    if let Some(_) = messaging_write.received_message {
                                        log.push_str(&format!(
                                            "\n{}",
                                            "IF NONE, SOMETHING IS WRONG!".red()
                                        ));
                                    } else {
                                        log.push_str(&format!(
                                            "\n{} {:?}",
                                            "AND RECEIVED:".green(),
                                            message.packets.len()
                                        ));
                                    }
                                    messaging_write.received_message =
                                        Some((Instant::now(), message));

                                    log.push_str(&format!("\n{}", "AND DONE".purple()));
                                    println!("{}", log.bright_blue());
                                    return ReadClientBytesResult::CompletedMessagePartSend;
                                } else {
                                    println!("{}", log.bright_blue());
                                    return ReadClientBytesResult::InvalidDeserializedMessage;
                                }
                            } else {
                                log.push_str(&format!("\n{}", "AND DONE".purple()));
                                println!("{}", log.bright_blue());
                                return ReadClientBytesResult::ValidMessagePartSend;
                            }
                        } else {
                            log.push_str(&format!("\n{}", "AND DONE".purple()));
                            println!("{}", log.bright_blue());
                            return ReadClientBytesResult::AlreadyAssignedMessagePartSend;
                        }
                    } else {
                        return ReadClientBytesResult::InvalidMessagePart;
                    }
                }
                _ => {
                    return ReadClientBytesResult::InvalidChannelEntry;
                }
            }
        } else {
            return ReadClientBytesResult::ClientPoisoned;
        }
    } else if server.clients_to_try_auth.contains_key(&addr) {
        return ReadClientBytesResult::OverflowAuthenticationRequest;
    } else {
        return match handle_authentication(bytes, server, addr) {
            Ok(result) => result,
            Err(e) => ReadClientBytesResult::InvalidAuthenticationRequest(e),
        };
    }
}

fn handle_authentication(
    bytes: Vec<u8>,
    server: &Arc<Server>,
    addr: SocketAddr,
) -> Result<ReadClientBytesResult, io::Error> {
    if bytes[0] != MessageChannel::MESSAGE_PART_SEND {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong channel"));
    }

    let part = MessagePart::deserialize(bytes[1..].to_vec())?;
    let mut tree: BTreeMap<MessagePartLargeId, MessagePart> = BTreeMap::new();
    tree.insert(0, part);

    let check = DeserializedMessageCheck::new(&tree)?;
    let message = DeserializedMessage::deserialize(&server.packet_registry, check, tree)?;

    server.clients_to_try_auth.insert(addr, message);
    Ok(ReadClientBytesResult::AuthenticationRequest)
}

fn create_client_packet_confirmation_thread(
    server: Arc<Server>,
    addr: SocketAddr,
    message_parts_to_confirm_receiver: crossbeam_channel::Receiver<MessagePartId>,
) {
    Arc::clone(&server.runtime).spawn(async move {
        while let Ok(id) = message_parts_to_confirm_receiver.recv() {
            let _ = server
                .socket
                .send_to(&vec![MessageChannel::MESSAGE_PART_CONFIRM, id], addr)
                .await;
        }
    });
}

fn create_client_packet_sending_thread(
    server: Arc<Server>,
    addr: SocketAddr,
    packets_to_send_receiver: crossbeam_channel::Receiver<Option<SerializedPacket>>,
    messaging: Arc<RwLock<ConnectedClientMessaging>>,
) {
    Arc::clone(&server.runtime).spawn(async move {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();
        let mut next_message_to_send_start_id =
            server.messaging_properties.initial_next_message_part_id;
        while let Ok(serialized_packet) = packets_to_send_receiver.recv() {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                let packets_to_send =
                    std::mem::replace(&mut packets_to_send, Vec::new());

                let bytes = SerializedPacketList::create(packets_to_send).bytes;
                if let Ok(message_parts) = MessagePart::create_list(
                    bytes,
                    &server.messaging_properties,
                    next_message_to_send_start_id,
                ) {
                    if let Ok(mut messaging_write) = messaging.write() {
                        messaging_write.last_sent_message = Instant::now();
                    }else {
                        break;
                    }

                    next_message_to_send_start_id =
                        message_parts[message_parts.len() - 1].id().wrapping_add(1);

                    let mut large_id = message_parts[0].id() as MessagePartLargeId;
                    println!(
                        "{}",
                        format!(
                            "[ASYNC] [send_packets_to_server_future] start sending parts: `{:?}",
                            message_parts
                                .iter()
                                .map(|part| part.id().to_string())
                                .collect::<Vec<String>>()
                        )
                        .on_magenta()
                    );
                    for part in message_parts {
                        let bytes = part.clone_bytes_with_channel();
                        let TODO_REMOVE_THIS = part.id();

                        {
                            if let Ok(mut messaging_write) = messaging.write() {
                                messaging_write.pending_client_confirmation.insert(large_id, (Instant::now(), part));
                            }else {
                                break;
                            }
                        }

                        let _ = server.socket.send_to(&bytes, addr).await;
                        println!("{}",format!(
                            "[ASYNC] [send_packets_to_client_future] message part id sent: {:?}, large id: {:?}, bytes size {:?} ",
                            TODO_REMOVE_THIS,large_id,bytes.len()
                        ).purple());

                        large_id += 1;
                    }
                }
            }
        }
    });
}

fn create_client_packet_loss_resending_thread(
    server: Arc<Server>,
    addr: SocketAddr,
    packet_loss_resending_receiver: crossbeam_channel::Receiver<MessagePartLargeId>,
    messaging: Arc<RwLock<ConnectedClientMessaging>>,
) {
    Arc::clone(&server.runtime).spawn(async move {
        while let Ok(large_id) = packet_loss_resending_receiver.recv() {
            let mut bytes: Option<Vec<u8>> = None;
            if let Ok(messaging) = messaging.read() {
                if let Some((_, part)) = messaging.pending_client_confirmation.get(&large_id) {
                    bytes = Some(part.clone_bytes_with_channel());
                }
            }

            if let Some(bytes) = bytes {
                let _ = server.socket.send_to(&bytes, addr).await;
                println!(
                    "{}",
                    format!(
                        "[ASYNC] [PACKET LOSS] message part len sent: {:?} ",
                        bytes.len()
                    )
                    .purple()
                );
            }
        }
    });
}

fn add_read_handler(server: Arc<Server>) {
    Arc::clone(&server.runtime).spawn(async move {
        let mut was_used = false;
        *server.read_handler_properties.surplus_count.lock().await += 1;
        loop {
            if *server.read_handler_properties.surplus_count.lock().await
                > server.read_handler_properties.surplus_target_size + 1
            {
                let mut surplus_count = server.read_handler_properties.surplus_count.lock().await;
                if !was_used {
                    *surplus_count -= 1;
                }
                break;
            } else {
                match timeout(
                    server.read_handler_properties.surplus_timeout,
                    pre_read_next_bytes(&server),
                )
                .await
                {
                    Ok(tuple) => {
                        //TODO: handle errors
                        let tuple = tuple.unwrap();
                        if !was_used {
                            was_used = true;
                            let mut surplus_count =
                                server.read_handler_properties.surplus_count.lock().await;
                            *surplus_count -= 1;
                        }

                        //TODO: use this
                        let read_handler = read_next_bytes(&server, tuple).await;
                        println!(
                            "{}",
                            format!("[READ_HANDLER] result: {:?}", read_handler).blue()
                        );
                    }
                    Err(_) => {
                        if was_used {
                            was_used = false;
                            let mut surplus_count =
                                server.read_handler_properties.surplus_count.lock().await;
                            *surplus_count += 1;
                        }
                    }
                }
            }
        }
    });
}
