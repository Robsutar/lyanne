use std::{
    cmp::Ordering,
    collections::BTreeMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock, RwLockWriteGuard},
    time::Instant,
};

use tokio::{net::UdpSocket, runtime::Runtime, time::timeout};

use crate::{
    messages::{
        DeserializedMessage, DeserializedMessageCheck, MessagePart, MessagePartId,
        MessagePartLargeId,
    },
    packets::{
        ClientTickCalledPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList,
    },
    utils,
};
use colored::*;

use super::{MessageChannel, MessagingProperties};

/// Possible results when receiving bytes by client
#[derive(Debug, Clone, Copy)]
pub enum ReadServerBytesResult {
    CompletedMessagePartSend,
    ValidMessagePartSend,
    AlreadyAssignedMessagePartSend,
    ValidMessagePartConfirm,
    AlreadyAssignedMessagePartConfirm,
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
    pub client_read: Arc<ClientRead>,
    pub client_async: Arc<RwLock<ClientAsync>>,
    pub client_mut: ClientMut,
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

/// Read-only properties of the client
///
/// Intended to be used with [`Arc`]
pub struct ClientRead {
    pub remote_addr: SocketAddr,
    pub socket: UdpSocket,
    pub runtime: Arc<Runtime>,
    pub packet_registry: Arc<PacketRegistry>,
    pub messaging_properties: Arc<MessagingProperties>,
}

/// Read-only properties of the client, but mutable at [`tick()`]
///
/// Intended to be used with [`RwLock`]
pub struct ClientAsync {
    pub connected_server: ConnectedServerAsync,
    pub disconnected: Option<DisconnectReason>,
}

/// Mutable properties of the client
///
/// Not intended to be shared between threads
pub struct ClientMut {
    pub connected_server: ConnectedServerMut,
    last_received_message: Instant,
}

/// Mutable and shared between threads properties of the connected server
///
/// Intended to be used inside [`ClientAsync`]
pub struct ConnectedServerAsync {
    next_message_to_receive_start_id: MessagePartId,
    next_message_to_send_start_id: MessagePartId,
    pending_server_confirmation: BTreeMap<MessagePartLargeId, (Instant, MessagePart)>,
    incoming_messages: BTreeMap<MessagePartLargeId, MessagePart>,
    received_message: Option<DeserializedMessage>,
}

/// Mutable properties of the connected server
///
/// Intended to be used inside [`ClientMut`]
pub struct ConnectedServerMut {
    packets_to_send: Vec<SerializedPacket>,
}

impl ConnectedServerMut {
    pub fn send<P: Packet>(&mut self, client_read: &ClientRead, packet: &P) -> io::Result<()> {
        let serialized = client_read.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&mut self, serialized_packet: SerializedPacket) {
        self.packets_to_send.push(serialized_packet);
    }
}

/// Connect to a server via a [`UdpSocket`], creating a new Client instance
pub async fn connect(
    remote_addr: SocketAddr,
    packet_registry: Arc<PacketRegistry>,
    messaging_properties: Arc<MessagingProperties>,
    runtime: Arc<Runtime>,
    authentication_packets: Vec<SerializedPacket>,
) -> io::Result<ConnectResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote_addr).await?;

    let client_read = Arc::new(ClientRead {
        remote_addr,
        socket,
        runtime,
        packet_registry,
        messaging_properties,
    });
    let client_async = Arc::new(RwLock::new(ClientAsync {
        connected_server: ConnectedServerAsync {
            next_message_to_receive_start_id: client_read
                .messaging_properties
                .initial_next_message_part_id,
            next_message_to_send_start_id: client_read
                .messaging_properties
                .initial_next_message_part_id,
            pending_server_confirmation: BTreeMap::new(),
            incoming_messages: BTreeMap::new(),
            received_message: None,
        },
        disconnected: None,
    }));
    let mut client_mut = ClientMut {
        connected_server: ConnectedServerMut {
            packets_to_send: Vec::new(),
        },
        last_received_message: Instant::now(),
    };

    {
        let bytes = SerializedPacketList::create(authentication_packets).bytes;
        let parts = MessagePart::create_list(
            bytes,
            &client_read.messaging_properties,
            client_read
                .messaging_properties
                .initial_next_message_part_id,
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

        client_read
            .socket
            .send(&parts[0].clone_bytes_with_channel())
            .await?;
        println!("[CONNECTING] message part id sent: {:?} ", parts[0].id());
    }

    let read_handler =
        read_handler_schedule(Arc::clone(&client_read), Arc::clone(&client_async)).await;

    if let Err(err) = read_handler {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Error reading first confirmation message: {:?}", err),
        ));
    }
    let tick = tick(
        Arc::clone(&client_read),
        Arc::clone(&client_async),
        Arc::clone(&client_async).write().unwrap(),
        &mut client_mut,
    );
    match tick {
        ClientTickResult::ReceivedMessage(message) => {
            let read_handler_client_read = Arc::clone(&client_read);
            let read_handler_client_async = Arc::clone(&client_async);
            Arc::clone(&client_read.runtime).spawn(async move {
                let client_read = read_handler_client_read;
                let client_async = read_handler_client_async;
                loop {
                    if let Ok(client_async_read) = client_async.read() {
                        if let Some(_) = client_async_read.disconnected {
                            break;
                        }
                    } else {
                        break;
                    }

                    let read_handler =
                        read_handler_schedule(Arc::clone(&client_read), Arc::clone(&client_async))
                            .await;

                    if let Err(_) = read_handler {
                        break;
                    }
                    println!(
                        "{}",
                        format!("[READ_HANDLER] result: {:?}", read_handler).blue()
                    );
                }
            });

            return Ok(ConnectResult {
                client_read,
                client_async,
                client_mut,
                message,
            });
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
pub fn tick(
    client_read: Arc<ClientRead>,
    client_async: Arc<RwLock<ClientAsync>>,
    mut client_async_write: RwLockWriteGuard<ClientAsync>,
    client_mut: &mut ClientMut,
) -> ClientTickResult {
    if let Some(reason) = client_async_write.disconnected {
        return ClientTickResult::Disconnect(reason);
    }

    let now = Instant::now();

    if now - client_mut.last_received_message
        >= client_read.messaging_properties.timeout_interpretation
    {
        let reason = DisconnectReason::MessageReceiveTimeout;
        client_async_write.disconnected = Some(reason);
        return ClientTickResult::Disconnect(reason);
    }

    let tick_packet_serialized = client_read
        .packet_registry
        .serialize(&ClientTickCalledPacket)
        .unwrap();

    let server_async = &mut client_async_write.connected_server;
    let server_mut = &mut client_mut.connected_server;

    if server_async.pending_server_confirmation.is_empty() {
        if let Some(message) = server_async.received_message.take() {
            client_mut.last_received_message = now;

            server_mut.send_packet_serialized(SerializedPacket::clone(&tick_packet_serialized));
            let packets_to_send = std::mem::replace(&mut server_mut.packets_to_send, Vec::new());

            Arc::clone(&client_read.runtime).spawn(send_packets_to_server_future(
                Arc::clone(&client_read),
                Arc::clone(&client_async),
                packets_to_send,
            ));

            return ClientTickResult::ReceivedMessage(message);
        } else {
            return ClientTickResult::PendingMessage;
        }
    } else {
        let mut packet_loss_count: MessagePartLargeId = 0;
        for (_, (ref mut instant, part)) in server_async.pending_server_confirmation.iter_mut() {
            if now - *instant >= client_read.messaging_properties.timeout_interpretation {
                let reason = DisconnectReason::PendingMessageConfirmationTimeout;
                client_async_write.disconnected = Some(reason);
                return ClientTickResult::Disconnect(reason);
            }
            if now - *instant >= client_read.messaging_properties.packet_loss_interpretation {
                *instant = now;
                packet_loss_count += 1;
                let client_read = Arc::clone(&client_read);
                let bytes = part.clone_bytes_with_channel();
                let TODO_REMOVE_THIS = part.id();
                Arc::clone(&client_read.runtime).spawn(async move {
                    let _ = client_read.socket.send(&bytes).await;
                    println!(
                        "{}",
                        format!(
                            "[ASYNC] [PACKET LOSS] message part id sent: {:?} ",
                            TODO_REMOVE_THIS
                        )
                        .bold()
                        .on_blue()
                    );
                });
            }
        }
        return ClientTickResult::PacketLossHandling(packet_loss_count);
    }
}

/// Read bytes for some client, just using a reference of ClientRead
pub async fn pre_read_next_bytes(client_read: &Arc<ClientRead>) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1024];
    let len = client_read.socket.recv(&mut buf).await?;
    Ok(buf[..len].to_vec())
}

/// Uses bytes read by [`pre_read_next_bytes()`] and processes them
///
/// # Returns
///
/// The result of processing those bytes. If the result is invalid
/// (check it with[`ReadServerBytesResult::is_valid()`]), ignoring or
/// disconnecting from the server is recommended.
pub async fn read_next_bytes(
    client_read: &Arc<ClientRead>,
    client_async: &Arc<RwLock<ClientAsync>>,
    bytes: Vec<u8>,
) -> ReadServerBytesResult {
    println!("{} {:?}", "bytes: ".red(), bytes.len());
    if bytes.len() < 2 {
        return ReadServerBytesResult::InsufficientBytesLen;
    }

    //TODO: remove this
    if true {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        if rng.gen_bool(0.1) {
            println!("{}", "packet loss simulation!!!".red());
            return ReadServerBytesResult::PacketLossSimulation;
        }
    }

    if let Ok(client_async_read) = client_async.read() {
        match bytes[0] {
            MessageChannel::MESSAGE_PART_CONFIRM => {
                drop(client_async_read);
                if let Ok(mut client_async_write) = client_async.write() {
                    let server_async = &mut client_async_write.connected_server;
                    let REMOVE_VAR = utils::remove_with_rotation(
                        &mut server_async.pending_server_confirmation,
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
                                server_async.pending_server_confirmation.keys()
                            )
                            .red()
                        );
                        return ReadServerBytesResult::AlreadyAssignedMessagePartConfirm;
                    }
                } else {
                    return ReadServerBytesResult::ClientAsyncPoisoned;
                }
            }
            MessageChannel::MESSAGE_PART_SEND => {
                let server_async = &client_async_read.connected_server;
                if let Some(_) = server_async.received_message {
                    return ReadServerBytesResult::ClosedMessageChannel;
                }
                if let Ok(part) = MessagePart::deserialize(bytes[1..].to_vec()) {
                    let next_message_to_receive_start_id =
                        server_async.next_message_to_receive_start_id;
                    let mut log = String::new();

                    log.push_str(&format!(
                        "\n part received {:?} {:?}",
                        part.id(),
                        next_message_to_receive_start_id
                    ));
                    log.push_str(&format!("\n   sending confirmation"));
                    send_message_part_confirmation(Arc::clone(&client_read), part.id());
                    if Ordering::Less
                        != utils::compare_with_rotation(part.id(), next_message_to_receive_start_id)
                    {
                        drop(client_async_read);
                        if let Ok(mut client_async_write) = client_async.write() {
                            let server_async = &mut client_async_write.connected_server;
                            let large_index: MessagePartLargeId = {
                                if part.id() >= next_message_to_receive_start_id {
                                    part.id() as MessagePartLargeId
                                } else {
                                    part.id() as MessagePartLargeId + 256
                                }
                            };

                            server_async.incoming_messages.insert(large_index, part);
                            log.push_str(&format!(
                                "\n     large_index: {:?}, actual incoming_messages size: {:?}, keys: {:?}",
                                large_index,
                                server_async.incoming_messages.len(),
                                server_async.incoming_messages.keys()
                            ));
                            if let Ok(check) =
                                DeserializedMessageCheck::new(&server_async.incoming_messages)
                            {
                                log.push_str(&format!("\n       ok check",));
                                let incoming_messages = std::mem::replace(
                                    &mut server_async.incoming_messages,
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
                                    &client_read.packet_registry,
                                    check,
                                    incoming_messages,
                                ) {
                                    log.push_str(&format!("\n         deserializing"));
                                    server_async.next_message_to_receive_start_id =
                                        new_next_message_to_receive_start_id;

                                    if let Some(_) = server_async.received_message {
                                        log.push_str(&format!("\n IF NONE, SOMETHING IS WRONG!"))
                                    } else {
                                        log.push_str(&format!(
                                            "\n           AND RECEIVED: {:?}",
                                            message.packets.len()
                                        ));
                                    }
                                    server_async.received_message = Some(message);

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
                            log.push_str(&format!("       AND ERROR ClientAsyncPoisoned",));
                            println!("{}", log.purple());
                            return ReadServerBytesResult::ClientAsyncPoisoned;
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

fn send_message_part_confirmation(server_read: Arc<ClientRead>, id: u8) {
    Arc::clone(&server_read.runtime).spawn(async move {
        let _ = server_read
            .socket
            .send(&vec![MessageChannel::MESSAGE_PART_CONFIRM, id])
            .await;
    });
}

fn send_packets_to_server_future(
    client_read: Arc<ClientRead>,
    client_async: Arc<RwLock<ClientAsync>>,
    packets_to_send: Vec<SerializedPacket>,
) -> impl Future<Output = ()> {
    async move {
        if let Ok(client_async_read) = client_async.read() {
            let server_async = &client_async_read.connected_server;
            let bytes = SerializedPacketList::create(packets_to_send).bytes;
            if let Ok(message_parts) = MessagePart::create_list(
                bytes,
                &client_read.messaging_properties,
                server_async.next_message_to_send_start_id,
            ) {
                drop(client_async_read);
                if let Ok(mut client_async_write) = client_async.write() {
                    let server_async = &mut client_async_write.connected_server;
                    server_async.next_message_to_send_start_id =
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
                        let client_read = Arc::clone(&client_read);
                        let bytes = part.clone_bytes_with_channel();
                        let TODO_REMOVE_THIS = part.id();
                        Arc::clone(&client_read.runtime).spawn(async move {
                            let _ = client_read.socket.send(&bytes).await;
                            println!("{}",format!(
                                "[ASYNC] [send_packets_to_server_future] message part id sent: {:?}, large id: {:?}",
                                TODO_REMOVE_THIS, large_id
                            ).purple());
                        });

                        server_async
                            .pending_server_confirmation
                            .insert(large_id, (Instant::now(), part));
                        large_id += 1;
                    }
                }
            }
        }
    }
}

async fn read_handler_schedule(
    client_read: Arc<ClientRead>,
    client_async: Arc<RwLock<ClientAsync>>,
) -> io::Result<ReadServerBytesResult> {
    match timeout(
        client_read.messaging_properties.timeout_interpretation,
        pre_read_next_bytes(&client_read),
    )
    .await
    {
        Ok(bytes) => {
            let bytes: Vec<u8> = bytes?;

            return Ok(read_next_bytes(&client_read, &client_async, bytes).await);
        }
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Timeout, elapsed: {:?}", e),
            ));
        }
    }
}
