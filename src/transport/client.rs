use std::{
    cmp::Ordering,
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

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
        ClientTickCalledPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList,
    },
    utils::{self, DurationMonitor},
};

use colored::*;

use super::{MessageChannel, MessagingProperties};

#[cfg(feature = "troubles_simulator")]
use super::troubles_simulator::NetTroublesSimulatorProperties;

/// Possible results when receiving bytes by client
#[derive(Debug, Clone, Copy)]
pub enum ReadServerBytesResult {
    CompletedMessagePartSend,
    ValidMessagePartSend,
    AlreadyAssignedMessagePartSend,
    ValidMessagePartConfirm,
    AlreadyAssignedMessagePartConfirm,
    #[cfg(feature = "troubles_simulator")]
    PacketLossSimulation,
    ClosedMessageChannel,
    InvalidChannelEntry,
    InsufficientBytesLen,
    InvalidMessagePart,
    InvalidDeserializedMessage,
    ClientAsyncPoisoned,
}

impl ReadServerBytesResult {
    /// Default validation of client sent bytes interpretation result
    /// # Returns
    ///
    /// false if the result is not considered as valid, so, can be interpreted
    /// that the client sent an invalid data, and should be ignored/disconnected
    pub fn is_valid(&self) -> bool {
        match self {
            ReadServerBytesResult::CompletedMessagePartSend => true,
            ReadServerBytesResult::ValidMessagePartSend => true,
            ReadServerBytesResult::AlreadyAssignedMessagePartSend => true,
            ReadServerBytesResult::ValidMessagePartConfirm => true,
            ReadServerBytesResult::AlreadyAssignedMessagePartConfirm => true,
            #[cfg(feature = "troubles_simulator")]
            ReadServerBytesResult::PacketLossSimulation => true,
            ReadServerBytesResult::ClosedMessageChannel => true,
            ReadServerBytesResult::InvalidChannelEntry => false,
            ReadServerBytesResult::InsufficientBytesLen => false,
            ReadServerBytesResult::InvalidMessagePart => false,
            ReadServerBytesResult::InvalidDeserializedMessage => false,
            ReadServerBytesResult::ClientAsyncPoisoned => false,
        }
    }
}

/// Possible reasons to be disconnected from the server
#[derive(Debug, Clone, Copy)]
pub enum DisconnectReason {
    PendingMessageConfirmationTimeout,
    MessageReceiveTimeout,
}

/// Result when calling [`connect()`]
pub struct ConnectResult {
    pub client: Arc<Client>,
    pub message: DeserializedMessage,
}

/// Result when calling [`tick()`]
#[derive(Debug)]
pub enum ClientTickResult {
    ReceivedMessage(DeserializedMessage),
    PacketLossHandling(MessagePartLargeId),
    PendingMessage,
    Disconnect(DisconnectReason),
}

/// Properties of the client
///
/// Intended to be used with [`Arc`]
pub struct Client {
    // Read
    pub remote_addr: SocketAddr,
    pub socket: UdpSocket,
    pub runtime: Arc<Runtime>,
    pub packet_registry: Arc<PacketRegistry>,
    pub messaging_properties: Arc<MessagingProperties>,
    #[cfg(feature = "troubles_simulator")]
    pub net_troubles_simulator: Option<Arc<NetTroublesSimulatorProperties>>,

    // Write
    pub connected_server: ConnectedServer,
    pub disconnected: Arc<RwLock<Option<DisconnectReason>>>,
}

/// Messaging fields of [`ConnectedServer`]
///
/// Intended to be used with [`Arc`] and [`RwLock`]
pub struct ConnectedServerMessaging {
    next_message_to_receive_start_id: MessagePartId,
    pending_server_confirmation: BTreeMap<MessagePartLargeId, (Instant, MessagePart)>,
    incoming_messages: BTreeMap<MessagePartLargeId, MessagePart>,
    received_message: Option<(Instant, DeserializedMessage)>,
    last_received_message: Instant,
    last_sent_message: Instant,
    latency_monitor: DurationMonitor,
}

/// Mutable and shared between threads properties of the connected server
///
/// Intended to be used inside [`ClientAsync`]
pub struct ConnectedServer {
    messaging: Arc<RwLock<ConnectedServerMessaging>>,
    average_latency: RwLock<Duration>,
    packets_to_send_sender: crossbeam_channel::Sender<Option<SerializedPacket>>,
    message_parts_to_confirm_sender: crossbeam_channel::Sender<MessagePartId>,
    packet_loss_resending_sender: crossbeam_channel::Sender<MessagePartLargeId>,
}

impl ConnectedServer {
    pub fn send<P: Packet>(&self, client: &Client, packet: &P) -> io::Result<()> {
        let serialized = client.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&self, serialized_packet: SerializedPacket) {
        self.packets_to_send_sender
            .send(Some(serialized_packet))
            .unwrap();
    }

    /// # Returns
    /// The average time of messaging response of the server after a client message + server tick delay
    pub fn average_latency(&self) -> Duration {
        *self.average_latency.read().unwrap()
    }
}

/// Connect to a server via a [`UdpSocket`], creating a new Client instance
pub async fn connect(
    remote_addr: SocketAddr,
    packet_registry: Arc<PacketRegistry>,
    messaging_properties: Arc<MessagingProperties>,
    #[cfg(feature = "troubles_simulator")] net_troubles_simulator: Option<
        Arc<NetTroublesSimulatorProperties>,
    >,
    runtime: Arc<Runtime>,
    authentication_packets: Vec<SerializedPacket>,
) -> io::Result<ConnectResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote_addr).await?;

    let (packets_to_send_sender, packets_to_send_receiver) = crossbeam_channel::unbounded();
    let (message_parts_to_confirm_sender, message_parts_to_confirm_receiver) =
        crossbeam_channel::unbounded();
    let (packet_loss_resending_sender, packet_loss_resending_receiver) =
        crossbeam_channel::unbounded();

    let initial_next_message_part_id = messaging_properties.initial_next_message_part_id;

    let client = Arc::new(Client {
        remote_addr,
        socket,
        runtime,
        packet_registry,
        messaging_properties,
        #[cfg(feature = "troubles_simulator")]
        net_troubles_simulator,

        connected_server: ConnectedServer {
            messaging: Arc::new(RwLock::new(ConnectedServerMessaging {
                next_message_to_receive_start_id: initial_next_message_part_id,
                pending_server_confirmation: BTreeMap::new(),
                incoming_messages: BTreeMap::new(),
                received_message: None,
                last_received_message: Instant::now(),
                last_sent_message: Instant::now(),
                latency_monitor: DurationMonitor::filled_with(Duration::from_millis(50), 10),
            })),
            average_latency: RwLock::new(Duration::from_millis(50)),
            packets_to_send_sender,
            message_parts_to_confirm_sender,
            packet_loss_resending_sender,
        },
        disconnected: Arc::new(RwLock::new(None)),
    });

    {
        let bytes = SerializedPacketList::create(authentication_packets).bytes;
        let parts = MessagePart::create_list(
            bytes,
            &client.messaging_properties,
            client.messaging_properties.initial_next_message_part_id,
        )?;

        if parts.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Authentication packets as message parts size should be 1, but was {:?}",
                    parts.len()
                ),
            ));
        }

        client
            .socket
            .send(&parts[0].clone_bytes_with_channel())
            .await?;
        println!("[CONNECTING] message part id sent: {:?} ", parts[0].id());
    }

    let read_handler = read_handler_schedule(Arc::clone(&client)).await;

    if let Err(err) = read_handler {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Error reading first confirmation message: {:?}", err),
        ));
    }
    let tick = tick(Arc::clone(&client));
    match tick {
        ClientTickResult::ReceivedMessage(message) => {
            let read_handler_client = Arc::clone(&client);
            Arc::clone(&client.runtime).spawn(async move {
                let client = read_handler_client;
                loop {
                    if let Ok(reason) = client.disconnected.read() {
                        if reason.is_some() {
                            break;
                        }
                    } else {
                        break;
                    }

                    let read_handler = read_handler_schedule(Arc::clone(&client)).await;

                    if let Err(_) = read_handler {
                        break;
                    }
                    println!(
                        "{}",
                        format!("[READ_HANDLER] result: {:?}", read_handler).blue()
                    );
                }
            });

            create_server_packet_confirmation_thread(
                Arc::clone(&client),
                message_parts_to_confirm_receiver,
            );

            create_server_packet_sending_thread(
                Arc::clone(&client),
                packets_to_send_receiver,
                Arc::clone(&client.connected_server.messaging),
            );

            create_server_packet_loss_resending_thread(
                Arc::clone(&client),
                packet_loss_resending_receiver,
                Arc::clone(&client.connected_server.messaging),
            );

            return Ok(ConnectResult { client, message });
        }
        ClientTickResult::PacketLossHandling(_) | ClientTickResult::PendingMessage => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Missing first message from server"),
            ))
        }
        ClientTickResult::Disconnect(e) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Disconnect error: {:?}", e),
            ))
        }
    }
}

/// Client main tick
/// - Handles packet loss
/// - Handles timeout
/// - Sends [`packets_to_send`] to the server
/// - Handles messages received from the server
///
/// # Returns
/// - Received messages from the server
/// - Handles disconnection due to timeout or other reasons
///
pub fn tick(client: Arc<Client>) -> ClientTickResult {
    if let Some(reason) = *client.disconnected.read().unwrap() {
        return ClientTickResult::Disconnect(reason);
    }

    let now = Instant::now();

    let server = &client.connected_server;
    //TODO: unstead write() use try_write
    let mut messaging_write = server.messaging.write().unwrap();

    if now - messaging_write.last_received_message
        >= client.messaging_properties.timeout_interpretation
    {
        let reason = DisconnectReason::MessageReceiveTimeout;
        let mut disconnected = client.disconnected.write().unwrap();
        *disconnected = Some(reason);
        return ClientTickResult::Disconnect(reason);
    }

    if messaging_write.pending_server_confirmation.is_empty() {
        if let Some((time, message)) = messaging_write.received_message.take() {
            let delay = time - messaging_write.last_sent_message;
            messaging_write.latency_monitor.push(delay);
            let average_latency = messaging_write.latency_monitor.average_duration();
            *server.average_latency.write().unwrap() = average_latency;

            println!(
                "{}",
                format!(
                    "last ping-pong delay: {:?}, average latency: {:?}",
                    delay, average_latency
                )
                .bright_black()
            );
            messaging_write.last_received_message = time;

            server.send_packet_serialized(
                client
                    .packet_registry
                    .serialize(&ClientTickCalledPacket)
                    .unwrap(),
            );

            server.packets_to_send_sender.send(None).unwrap();

            return ClientTickResult::ReceivedMessage(message);
        } else {
            return ClientTickResult::PendingMessage;
        }
    } else {
        let mut packet_loss_count: MessagePartLargeId = 0;
        for (large_id, (ref mut instant, _)) in
            messaging_write.pending_server_confirmation.iter_mut()
        {
            if now - *instant >= client.messaging_properties.timeout_interpretation {
                let reason = DisconnectReason::PendingMessageConfirmationTimeout;
                let mut disconnected = client.disconnected.write().unwrap();
                *disconnected = Some(reason);
                return ClientTickResult::Disconnect(reason);
            }
            if now - *instant >= client.messaging_properties.packet_loss_interpretation {
                *instant = now;
                let _ = server.packet_loss_resending_sender.send(*large_id);
                packet_loss_count += 1;
            }
        }
        return ClientTickResult::PacketLossHandling(packet_loss_count);
    }
}

/// Read bytes for some client, just using a reference of ClientRead
pub async fn pre_read_next_bytes(client: &Arc<Client>) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1024];
    let len = client.socket.recv(&mut buf).await?;
    Ok(buf[..len].to_vec())
}

/// Uses bytes read by [`pre_read_next_bytes()`] and processes them
///
/// # Returns
///
/// The result of processing those bytes. If the result is invalid
/// (check it with[`ReadServerBytesResult::is_valid()`]), ignoring or
/// disconnecting from the server is recommended.
pub async fn read_next_bytes(client: &Arc<Client>, bytes: Vec<u8>) -> ReadServerBytesResult {
    println!("{} {:?}", "bytes: ".red(), bytes.len());
    if bytes.len() < 2 {
        return ReadServerBytesResult::InsufficientBytesLen;
    }

    #[cfg(feature = "troubles_simulator")]
    if let Some(net_troubles_simulator) = &client.net_troubles_simulator {
        if net_troubles_simulator.ranged_packet_loss() {
            println!("{}", "packet loss simulation!!!".red());
            return ReadServerBytesResult::PacketLossSimulation;
        } else if let Some(delay) = net_troubles_simulator.ranged_ping_delay() {
            sleep(delay).await;
            println!("{}", format!("delay of {:?} was simulated!!!", delay).red());
        }
    }

    if let Ok(mut messaging_write) = client.connected_server.messaging.write() {
        match bytes[0] {
            MessageChannel::MESSAGE_PART_CONFIRM => {
                let REMOVE_VAR = utils::remove_with_rotation(
                    &mut messaging_write.pending_server_confirmation,
                    bytes[1],
                );
                if let Some(_) = REMOVE_VAR {
                    println!(
                        "{}",
                        format!("[MESSAGE_PART_CONFIRM] successfully removed {:?}", bytes[1])
                            .green()
                    );
                    return ReadServerBytesResult::ValidMessagePartConfirm;
                } else {
                    println!(
                        "{}",
                        format!(
                            "[MESSAGE_PART_CONFIRM] already removed {:?}, possible keys: {:?}",
                            bytes[1],
                            messaging_write.pending_server_confirmation.keys()
                        )
                        .red()
                    );
                    return ReadServerBytesResult::AlreadyAssignedMessagePartConfirm;
                }
            }
            MessageChannel::MESSAGE_PART_SEND => {
                let server = &client.connected_server;
                if let Some(_) = messaging_write.received_message {
                    return ReadServerBytesResult::ClosedMessageChannel;
                }
                if let Ok(part) = MessagePart::deserialize(bytes[1..].to_vec()) {
                    let next_message_to_receive_start_id =
                        messaging_write.next_message_to_receive_start_id;
                    let mut log = String::new();

                    log.push_str(&format!(
                        "\n part received {:?} {:?}",
                        part.id(),
                        next_message_to_receive_start_id
                    ));
                    log.push_str(&format!("\n   sending confirmation"));
                    let _ = server.message_parts_to_confirm_sender.send(part.id());
                    if Ordering::Less
                        != utils::compare_with_rotation(part.id(), next_message_to_receive_start_id)
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
                                    messaging_write.incoming_messages.keys()
                                ));
                        if let Ok(check) =
                            DeserializedMessageCheck::new(&messaging_write.incoming_messages)
                        {
                            log.push_str(&format!("\n       ok check",));
                            let incoming_messages = std::mem::replace(
                                &mut messaging_write.incoming_messages,
                                BTreeMap::new(),
                            );
                            let new_next_message_to_receive_start_id =
                                ((incoming_messages.last_key_value().unwrap().0 + 1) % 256)
                                    as MessagePartId;
                            log.push_str(&format!(
                                "\n       new_next_message_to_receive_start_id: IN {:?}",
                                new_next_message_to_receive_start_id
                            ));
                            if let Ok(message) = DeserializedMessage::deserialize(
                                &client.packet_registry,
                                check,
                                incoming_messages,
                            ) {
                                log.push_str(&format!("\n         deserializing"));
                                messaging_write.next_message_to_receive_start_id =
                                    new_next_message_to_receive_start_id;

                                if let Some(_) = messaging_write.received_message {
                                    log.push_str(&format!("\n IF NONE, SOMETHING IS WRONG!"))
                                } else {
                                    log.push_str(&format!(
                                        "\n           AND RECEIVED: {:?}",
                                        message.packets.len()
                                    ));
                                }
                                messaging_write.received_message = Some((Instant::now(), message));

                                log.push_str(&format!("\n             AND DONE "));
                                println!("{}", log.purple());
                                return ReadServerBytesResult::CompletedMessagePartSend;
                            } else {
                                log.push_str(&format!(
                                    "\n           AND ERROR InvalidDeserializedMessage",
                                ));
                                println!("{}", log.purple());
                                return ReadServerBytesResult::InvalidDeserializedMessage;
                            }
                        } else {
                            log.push_str(&format!("\n             AND DONE "));
                            println!("{}", log.purple());
                            return ReadServerBytesResult::ValidMessagePartSend;
                        }
                    } else {
                        log.push_str(&format!("\n             AND DONE "));
                        println!("{}", log.purple());
                        return ReadServerBytesResult::AlreadyAssignedMessagePartSend;
                    }
                } else {
                    return ReadServerBytesResult::InvalidMessagePart;
                }
            }
            _ => {
                return ReadServerBytesResult::InvalidChannelEntry;
            }
        }
    } else {
        return ReadServerBytesResult::ClientAsyncPoisoned;
    }
}

fn create_server_packet_confirmation_thread(
    client: Arc<Client>,
    message_parts_to_confirm_receiver: crossbeam_channel::Receiver<MessagePartId>,
) {
    Arc::clone(&client.runtime).spawn(async move {
        while let Ok(id) = message_parts_to_confirm_receiver.recv() {
            let _ = client
                .socket
                .send(&vec![MessageChannel::MESSAGE_PART_CONFIRM, id])
                .await;
        }
    });
}

fn create_server_packet_sending_thread(
    client: Arc<Client>,
    packets_to_send_receiver: crossbeam_channel::Receiver<Option<SerializedPacket>>,
    messaging: Arc<RwLock<ConnectedServerMessaging>>,
) {
    Arc::clone(&client.runtime).spawn(async move {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();
        let mut next_message_to_send_start_id =
            client.messaging_properties.initial_next_message_part_id;
        while let Ok(serialized_packet) = packets_to_send_receiver.recv() {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                let packets_to_send =
                    std::mem::replace(&mut packets_to_send, Vec::new());

                let bytes = SerializedPacketList::create(packets_to_send).bytes;
                if let Ok(message_parts) = MessagePart::create_list(
                    bytes,
                    &client.messaging_properties,
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
                                messaging_write.pending_server_confirmation.insert(large_id, (Instant::now(), part));
                            }else {
                                break;
                            }
                        }

                        let _ = client.socket.send(&bytes).await;
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

fn create_server_packet_loss_resending_thread(
    client: Arc<Client>,
    packet_loss_resending_receiver: crossbeam_channel::Receiver<MessagePartLargeId>,
    messaging: Arc<RwLock<ConnectedServerMessaging>>,
) {
    Arc::clone(&client.runtime).spawn(async move {
        while let Ok(large_id) = packet_loss_resending_receiver.recv() {
            let mut bytes: Option<Vec<u8>> = None;
            if let Ok(messaging) = messaging.read() {
                if let Some((_, part)) = messaging.pending_server_confirmation.get(&large_id) {
                    bytes = Some(part.clone_bytes_with_channel());
                }
            }

            if let Some(bytes) = bytes {
                let _ = client.socket.send(&bytes).await;
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

async fn read_handler_schedule(client: Arc<Client>) -> io::Result<ReadServerBytesResult> {
    match timeout(
        client.messaging_properties.timeout_interpretation,
        pre_read_next_bytes(&client),
    )
    .await
    {
        Ok(bytes) => {
            let bytes: Vec<u8> = bytes?;

            let exit = Ok(read_next_bytes(&client, bytes).await);
            exit
        }
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Timeout, elapsed: {:?}", e),
            ));
        }
    }
}
