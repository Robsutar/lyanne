use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, Instant},
};

use colored::*;

use tokio::{net::UdpSocket, runtime::Runtime, time::timeout};

use crate::{
    messages::{
        DeserializedMessage, DeserializedMessageCheck, MessagePart, MessagePartId,
        MessagePartLargeId,
    },
    packets::{
        ConfirmAuthenticationPacket, Packet, PacketRegistry, SerializedPacket,
        SerializedPacketList, ServerTickCalledPacket,
    },
    utils,
};

use super::{MessageChannel, MessagingProperties};

/// Possible results when receiving bytes by clients
#[derive(Debug)]
pub enum ReadClientBytesResult {
    AuthenticationRequest,
    CompletedMessagePartSend,
    ValidMessagePartSend,
    AlreadyAssignedMessagePartSend,
    ValidMessagePartConfirm,
    AlreadyAssignedMessagePartConfirm,
    PacketLossSimulation,
    ClosedMessageChannel,
    OverflowAuthenticationRequest,
    InvalidAuthenticationRequest(io::Error),
    InvalidChannelEntry,
    ClientAsyncWriteNotFound,
    InsufficientBytesLen,
    InvalidMessagePart,
    InvalidDeserializedMessage,
    ServerAsyncPoisoned,
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
            ReadClientBytesResult::PacketLossSimulation => true,
            ReadClientBytesResult::ClosedMessageChannel => true,
            ReadClientBytesResult::OverflowAuthenticationRequest => false,
            ReadClientBytesResult::InvalidAuthenticationRequest(_) => false,
            ReadClientBytesResult::InvalidChannelEntry => false,
            ReadClientBytesResult::ClientAsyncWriteNotFound => false,
            ReadClientBytesResult::InsufficientBytesLen => false,
            ReadClientBytesResult::InvalidMessagePart => false,
            ReadClientBytesResult::InvalidDeserializedMessage => false,
            ReadClientBytesResult::ServerAsyncPoisoned => false,
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
    pub server_read: Arc<ServerRead>,
    pub server_async: Arc<RwLock<ServerAsync>>,
    pub server_mut: ServerMut,
}

/// Result when calling [`tick()`]
pub struct ServerTickResult {
    pub received_messages: Vec<(SocketAddr, DeserializedMessage)>,
    pub clients_to_auth: HashMap<SocketAddr, DeserializedMessage>,
    pub clients_disconnected: HashMap<SocketAddr, ClientDisconnectReason>,
}

/// Read-only properties of the server
///
/// Intended to use used with [`Arc`]
pub struct ServerRead {
    pub socket: UdpSocket,
    pub runtime: Arc<Runtime>,
    pub packet_registry: Arc<PacketRegistry>,
    pub messaging_properties: Arc<MessagingProperties>,
    pub read_handler_properties: Arc<ReadHandlerProperties>,
}

/// Read-only properties of the server, but mutable at [`tick()`]
///
/// Intended to use used with [`RwLock`]
pub struct ServerAsync {
    pub connected_clients: HashMap<SocketAddr, ConnectedClientAsync>,
    clients_to_auth: HashMap<SocketAddr, DeserializedMessage>,
}

/// Mutable properties of the server
///
/// Not intended to be shared between threads
pub struct ServerMut {
    pub connected_clients: HashMap<SocketAddr, ConnectedClientMut>,
    marked_to_set_authenticated: HashSet<SocketAddr>,
    marked_to_unset_authenticated: HashMap<SocketAddr, ClientDisconnectReason>,
}

impl ServerMut {
    /// Mark a client to be authenticated in the next tick
    pub fn set_authenticated(&mut self, addr: SocketAddr) {
        self.marked_to_unset_authenticated.remove(&addr);
        self.marked_to_set_authenticated.insert(addr);
    }

    /// Mark a client to be removed from authenticated clients in the next tick
    pub fn unset_authenticated(&mut self, addr: SocketAddr) {
        self.marked_to_set_authenticated.remove(&addr);
        self.marked_to_unset_authenticated
            .insert(addr, ClientDisconnectReason::ManualDisconnect);
    }
}

/// Mutable and shared between threads properties of the connected client
///
/// Intended to be used inside [`ServerAsync`]
pub struct ConnectedClientAsync {
    next_message_to_receive_start_id: MessagePartId,
    next_message_to_send_start_id: MessagePartId,
    pending_client_confirmation: BTreeMap<MessagePartLargeId, (Instant, MessagePart)>,
    incoming_messages: BTreeMap<MessagePartLargeId, MessagePart>,
    received_message: Option<DeserializedMessage>,
}

/// Mutable properties of the connected client
///
/// Intended to be used inside [`ServerMut`]
pub struct ConnectedClientMut {
    packets_to_send: Vec<SerializedPacket>,
    last_received_message: Instant,
}

impl ConnectedClientMut {
    pub fn send<P: Packet>(&mut self, server_read: &ServerRead, packet: &P) -> io::Result<()> {
        let serialized = server_read.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&mut self, serialized_packet: SerializedPacket) {
        self.packets_to_send.push(serialized_packet);
    }
}

/// Bind a [`UdpSocket´], to create a new Server instance
pub async fn bind(
    addr: SocketAddr,
    packet_registry: Arc<PacketRegistry>,
    messaging_properties: Arc<MessagingProperties>,
    read_handler_properties: Arc<ReadHandlerProperties>,
    runtime: Arc<Runtime>,
) -> io::Result<BindResult> {
    let socket = UdpSocket::bind(addr).await?;

    let server_read = Arc::new(ServerRead {
        socket,
        runtime,
        packet_registry,
        messaging_properties,
        read_handler_properties,
    });
    let server_async = Arc::new(RwLock::new(ServerAsync {
        connected_clients: HashMap::new(),
        clients_to_auth: HashMap::new(),
    }));
    let server_mut = ServerMut {
        connected_clients: HashMap::new(),
        marked_to_set_authenticated: HashSet::new(),
        marked_to_unset_authenticated: HashMap::new(),
    };

    for _ in 0..server_read.read_handler_properties.surplus_target_size {
        add_read_handler(Arc::clone(&server_read), Arc::clone(&server_async));
    }

    Ok(BindResult {
        server_read,
        server_async,
        server_mut,
    })
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
pub fn tick(
    server_read: Arc<ServerRead>,
    server_async: Arc<RwLock<ServerAsync>>,
    mut server_async_write: RwLockWriteGuard<ServerAsync>,
    server_mut: &mut ServerMut,
) -> ServerTickResult {
    let now = Instant::now();
    let mut received_messages: Vec<(SocketAddr, DeserializedMessage)> = Vec::new();
    let clients_to_connect =
        std::mem::replace(&mut server_mut.marked_to_set_authenticated, HashSet::new());
    let mut clients_to_disconnect: HashMap<SocketAddr, ClientDisconnectReason> = std::mem::replace(
        &mut server_mut.marked_to_unset_authenticated,
        HashMap::new(),
    );
    let mut pending_packets_to_send: Vec<(SocketAddr, Vec<SerializedPacket>)> = Vec::new();

    let tick_packet_serialized = server_read
        .packet_registry
        .serialize(&ServerTickCalledPacket)
        .unwrap();

    for (addr, client_mut) in server_mut.connected_clients.iter_mut() {
        if now - client_mut.last_received_message
            >= server_read.messaging_properties.timeout_interpretation
        {
            clients_to_disconnect
                .insert(addr.clone(), ClientDisconnectReason::MessageReceiveTimeout);
            break;
        }

        let addr = addr.clone();
        let client_async = server_async_write.connected_clients.get_mut(&addr).unwrap();

        client_mut.send_packet_serialized(SerializedPacket::clone(&tick_packet_serialized));

        if client_async.pending_client_confirmation.is_empty() {
            if let Some(message) = client_async.received_message.take() {
                client_mut.last_received_message = now;
                received_messages.push((addr.clone(), message));

                let packets_to_send =
                    std::mem::replace(&mut client_mut.packets_to_send, Vec::new());

                pending_packets_to_send.push((addr.clone(), packets_to_send));
            }
        } else {
            for (_, (ref mut instant, part)) in client_async.pending_client_confirmation.iter_mut()
            {
                if now - *instant >= server_read.messaging_properties.timeout_interpretation {
                    clients_to_disconnect.insert(
                        addr.clone(),
                        ClientDisconnectReason::PendingMessageConfirmationTimeout,
                    );
                    break;
                }
                if now - *instant >= server_read.messaging_properties.packet_loss_interpretation {
                    *instant = now;
                    let server_read = Arc::clone(&server_read);
                    let bytes = part.clone_bytes_with_channel();
                    let TODO_REMOVE_THIS = part.id();
                    Arc::clone(&server_read.runtime).spawn(async move {
                        let _ = server_read.socket.send_to(&bytes, addr).await;
                        println!(
                            "{}",
                            format!(
                                "[ASYNC] [PACKET LOSS] message part id sent: {:?} ",
                                TODO_REMOVE_THIS
                            )
                            .purple()
                        );
                    });
                }
            }
        }
    }

    let confirm_authentication_serialized = server_read
        .packet_registry
        .serialize(&ConfirmAuthenticationPacket)
        .unwrap();

    let mut log = String::new();
    for addr in clients_to_connect {
        log.push_str(&format!("trying connect {:?}", addr));
        if !server_mut.connected_clients.contains_key(&addr) {
            log.push_str(&format!("{}", "  connecting"));
            pending_packets_to_send.push((
                addr.clone(),
                vec![SerializedPacket::clone(&confirm_authentication_serialized)],
            ));

            server_async_write.connected_clients.insert(
                addr.clone(),
                ConnectedClientAsync {
                    next_message_to_receive_start_id: server_read
                        .messaging_properties
                        .initial_next_message_part_id,
                    next_message_to_send_start_id: server_read
                        .messaging_properties
                        .initial_next_message_part_id,
                    pending_client_confirmation: BTreeMap::new(),
                    incoming_messages: BTreeMap::new(),
                    received_message: None,
                },
            );
            server_mut.connected_clients.insert(
                addr,
                ConnectedClientMut {
                    packets_to_send: Vec::new(),
                    last_received_message: Instant::now(),
                },
            );
        }
    }

    let mut clients_disconnected: HashMap<SocketAddr, ClientDisconnectReason> = HashMap::new();

    for (addr, reason) in clients_to_disconnect {
        log.push_str(&format!("trying disconnect {:?} for {:?}", addr, reason));
        //TODO: that should never be false, that is here just for manual kick reasons
        if let Some(_) = server_mut.connected_clients.remove(&addr) {
            log.push_str(&format!("  done disconnect"));
            server_async_write.connected_clients.remove(&addr).unwrap();
            clients_disconnected.insert(addr, reason);
        }
    }

    if log.len() > 0 {
        println!("{}", log.red().bold());
    }

    let clients_to_auth =
        std::mem::replace(&mut server_async_write.clients_to_auth, HashMap::new());

    for (addr, packets_to_send) in pending_packets_to_send {
        Arc::clone(&server_read.runtime).spawn(send_packets_to_client_future(
            Arc::clone(&server_read),
            Arc::clone(&server_async),
            addr,
            packets_to_send,
        ));
    }

    Arc::clone(&server_read.runtime).spawn(async move {
        if *server_read
            .read_handler_properties
            .surplus_count
            .lock()
            .await
            < server_read.read_handler_properties.surplus_target_size - 1
        {
            add_read_handler(Arc::clone(&server_read), Arc::clone(&server_async));
        }
    });

    ServerTickResult {
        received_messages,
        clients_to_auth,
        clients_disconnected,
    }
}

/// Read bytes for some client, just using a reference of ServerRead
pub async fn pre_read_next_bytes(
    server_read: &Arc<ServerRead>,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut buf = [0u8; 1024];
    let (len, addr) = server_read.socket.recv_from(&mut buf).await?;
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
    server_read: &Arc<ServerRead>,
    server_async: &Arc<RwLock<ServerAsync>>,
    tuple: (SocketAddr, Vec<u8>),
) -> ReadClientBytesResult {
    println!("{} {:?}", "bytes: ".red(), tuple.1.len());
    let (addr, bytes) = tuple;
    if bytes.len() < 2 {
        return ReadClientBytesResult::InsufficientBytesLen;
    }

    // TODO: remove this
    if true {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        if rng.gen_bool(0.1) {
            println!("{}", "packet loss simulation!!!".red());
            return ReadClientBytesResult::PacketLossSimulation;
        }
    }

    if let Ok(server_async_read) = server_async.read() {
        if let Some(client_async) = server_async_read.connected_clients.get(&addr) {
            match bytes[0] {
                MessageChannel::MESSAGE_PART_CONFIRM => {
                    drop(server_async_read);
                    if let Ok(mut server_async_write) = server_async.write() {
                        if let Some(client_async) =
                            server_async_write.connected_clients.get_mut(&addr)
                        {
                            let REMOVE_VAR = utils::remove_with_rotation(
                                &mut client_async.pending_client_confirmation,
                                bytes[1],
                            );
                            if let Some(_) = REMOVE_VAR {
                                println!(
                                    "{}",
                                    format!(
                                        "[MESSAGE_PART_CONFIRM] successfully removed {:?}",
                                        bytes[1]
                                    )
                                    .green()
                                );
                                return ReadClientBytesResult::ValidMessagePartConfirm;
                            } else {
                                println!(
                                    "{}",
                                    format!(
                                        "[MESSAGE_PART_CONFIRM] already removed {:?}, possible keys: {:?}",
                                        bytes[1],client_async.pending_client_confirmation.keys(),
                                    )
                                    .red()
                                );
                                return ReadClientBytesResult::AlreadyAssignedMessagePartConfirm;
                            }
                        } else {
                            return ReadClientBytesResult::ClientAsyncWriteNotFound;
                        }
                    } else {
                        return ReadClientBytesResult::ServerAsyncPoisoned;
                    }
                }
                MessageChannel::MESSAGE_PART_SEND => {
                    if let Some(_) = client_async.received_message {
                        return ReadClientBytesResult::ClosedMessageChannel;
                    }
                    if let Ok(part) = MessagePart::deserialize(bytes[1..].to_vec()) {
                        let next_message_to_receive_start_id =
                            client_async.next_message_to_receive_start_id;
                        let mut log = String::new();

                        log.push_str(&format!(
                            "\n{} {:?} {:?}",
                            "part received".purple(),
                            part.id(),
                            next_message_to_receive_start_id
                        ));
                        log.push_str(&format!("\n  {}", "sending confirmation".purple()));
                        send_message_part_confirmation(
                            Arc::clone(&server_read),
                            addr.clone(),
                            part.id(),
                        );
                        if Ordering::Less
                            != utils::compare_with_rotation(
                                part.id(),
                                next_message_to_receive_start_id,
                            )
                        {
                            drop(server_async_read);
                            if let Ok(mut server_async_write) = server_async.write() {
                                if let Some(client_async) =
                                    server_async_write.connected_clients.get_mut(&addr)
                                {
                                    let large_index: MessagePartLargeId = {
                                        if part.id() >= next_message_to_receive_start_id {
                                            part.id() as MessagePartLargeId
                                        } else {
                                            part.id() as MessagePartLargeId + 256
                                        }
                                    };

                                    client_async.incoming_messages.insert(large_index, part);
                                    log.push_str(&format!(
                                        "\n     large_index: {:?}, actual incoming_messages size: {:?}, keys: {:?}",
                                        large_index,
                                        client_async.incoming_messages.len(),
                                        client_async.incoming_messages.keys(),
                                    ).purple());
                                    if let Ok(check) = DeserializedMessageCheck::new(
                                        &client_async.incoming_messages,
                                    ) {
                                        let incoming_messages = std::mem::replace(
                                            &mut client_async.incoming_messages,
                                            BTreeMap::new(),
                                        );
                                        let new_next_message_to_receive_start_id =
                                            ((incoming_messages.last_key_value().unwrap().0 + 1)
                                                % 256)
                                                as MessagePartId;
                                        log.push_str(&format!(
                                            "\n{} {:?}",
                                            "new_next_message_to_receive_start_id: IN".purple(),
                                            new_next_message_to_receive_start_id
                                        ));
                                        if let Ok(message) = DeserializedMessage::deserialize(
                                            &server_read.packet_registry,
                                            check,
                                            incoming_messages,
                                        ) {
                                            client_async.next_message_to_receive_start_id =
                                                new_next_message_to_receive_start_id;

                                            if let Some(_) = client_async.received_message {
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
                                            client_async.received_message = Some(message);

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
                                    log.push_str(&format!(
                                        "\n{}",
                                        "ClientAsyncWriteNotFound".red()
                                    ));
                                    println!("{}", log.bright_blue());
                                    return ReadClientBytesResult::ClientAsyncWriteNotFound;
                                }
                            } else {
                                log.push_str(&format!("\n{}", "ServerAsyncPoisoned".red()));
                                println!("{}", log.bright_blue());
                                return ReadClientBytesResult::ServerAsyncPoisoned;
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
        } else if server_async_read.clients_to_auth.contains_key(&addr) {
            return ReadClientBytesResult::OverflowAuthenticationRequest;
        } else {
            return match handle_authentication(
                bytes,
                server_read,
                server_async,
                addr,
                server_async_read,
            ) {
                Ok(result) => result,
                Err(e) => ReadClientBytesResult::InvalidAuthenticationRequest(e),
            };
        }
    } else {
        return ReadClientBytesResult::ServerAsyncPoisoned;
    }
}

fn send_message_part_confirmation(server_read: Arc<ServerRead>, addr: SocketAddr, id: u8) {
    Arc::clone(&server_read.runtime).spawn(async move {
        let _ = server_read
            .socket
            .send_to(&vec![MessageChannel::MESSAGE_PART_CONFIRM, id], addr)
            .await;
    });
}

fn handle_authentication(
    bytes: Vec<u8>,
    server_read: &Arc<ServerRead>,
    server_async: &Arc<RwLock<ServerAsync>>,
    addr: SocketAddr,
    server_async_read: RwLockReadGuard<ServerAsync>,
) -> Result<ReadClientBytesResult, io::Error> {
    if bytes[0] != MessageChannel::MESSAGE_PART_SEND {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong channel"));
    }

    let part = MessagePart::deserialize(bytes[1..].to_vec())?;
    let mut tree: BTreeMap<MessagePartLargeId, MessagePart> = BTreeMap::new();
    tree.insert(0, part);

    let check = DeserializedMessageCheck::new(&tree)?;
    let message = DeserializedMessage::deserialize(&server_read.packet_registry, check, tree)?;

    drop(server_async_read);
    return Ok(match server_async.write() {
        Ok(mut server_async_write) => {
            server_async_write.clients_to_auth.insert(addr, message);
            ReadClientBytesResult::AuthenticationRequest
        }
        Err(_) => ReadClientBytesResult::ServerAsyncPoisoned,
    });
}

fn send_packets_to_client_future(
    server_read: Arc<ServerRead>,
    server_async: Arc<RwLock<ServerAsync>>,
    addr: SocketAddr,
    packets_to_send: Vec<SerializedPacket>,
) -> impl Future<Output = ()> {
    async move {
        if let Ok(server_async_read) = server_async.read() {
            if let Some(client_async) = server_async_read.connected_clients.get(&addr) {
                let bytes = SerializedPacketList::create(packets_to_send).bytes;
                if let Ok(message_parts) = MessagePart::create_list(
                    bytes,
                    &server_read.messaging_properties,
                    client_async.next_message_to_send_start_id,
                ) {
                    drop(server_async_read);
                    if let Ok(mut server_async_write) = server_async.write() {
                        if let Some(client_async) =
                            server_async_write.connected_clients.get_mut(&addr)
                        {
                            client_async.next_message_to_send_start_id =
                                message_parts[message_parts.len() - 1].id().wrapping_add(1);

                            let mut large_id = message_parts[0].id() as MessagePartLargeId;
                            for part in message_parts {
                                let server_read = Arc::clone(&server_read);
                                let bytes = part.clone_bytes_with_channel();

                                let TODO_REMOVE_THIS = part.id();
                                Arc::clone(&server_read.runtime).spawn(async move {
                                    let _ = server_read.socket.send_to(&bytes, addr).await;
                                    println!("{}",format!(
                                        "[ASYNC] [send_packets_to_client_future] message part id sent: {:?}, large id: {:?}, bytes size {:?} ",
                                        TODO_REMOVE_THIS,large_id,bytes.len()
                                    ).purple());
                                });

                                client_async
                                    .pending_client_confirmation
                                    .insert(large_id, (Instant::now(), part));
                                large_id += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn add_read_handler(server_read: Arc<ServerRead>, server_async: Arc<RwLock<ServerAsync>>) {
    Arc::clone(&server_read.runtime).spawn(async move {
        let mut was_used = false;
        *server_read
            .read_handler_properties
            .surplus_count
            .lock()
            .await += 1;
        loop {
            if *server_read
                .read_handler_properties
                .surplus_count
                .lock()
                .await
                > server_read.read_handler_properties.surplus_target_size + 1
            {
                let mut surplus_count = server_read
                    .read_handler_properties
                    .surplus_count
                    .lock()
                    .await;
                if !was_used {
                    *surplus_count -= 1;
                }
                break;
            } else {
                match timeout(
                    server_read.read_handler_properties.surplus_timeout,
                    pre_read_next_bytes(&server_read),
                )
                .await
                {
                    Ok(tuple) => {
                        //TODO: handle errors
                        let tuple = tuple.unwrap();
                        if !was_used {
                            was_used = true;
                            let mut surplus_count = server_read
                                .read_handler_properties
                                .surplus_count
                                .lock()
                                .await;
                            *surplus_count -= 1;
                        }

                        //TODO: use this
                        let read_handler =
                            read_next_bytes(&server_read, &server_async, tuple).await;
                        println!(
                            "{}",
                            format!("[READ_HANDLER] result: {:?}", read_handler).blue()
                        );
                    }
                    Err(_) => {
                        if was_used {
                            was_used = false;
                            let mut surplus_count = server_read
                                .read_handler_properties
                                .surplus_count
                                .lock()
                                .await;
                            *surplus_count += 1;
                        }
                    }
                }
            }
        }
    });
}
