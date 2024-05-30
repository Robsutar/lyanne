use crossbeam_channel as crossbeam;
use tokio::{net::ToSocketAddrs, runtime::Runtime, time::timeout};

use crate::packets::{
    DeserializedPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList,
};

use super::Socket;
use rand::{thread_rng, Rng};
use std::{
    collections::HashMap,
    io::{self},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServerRead {
    /*TODO: pub(crate)*/ pub socket: Socket,
    /*TODO: pub(crate)*/ pub packet_registry: Arc<PacketRegistry>,
}

pub struct ServerShared {
    /*TODO: pub(crate)*/ pub connected_clients: HashMap<SocketAddr, ConnectedClientShared>,
    pub(crate) clients_to_auth_sender: crossbeam::Sender<(SocketAddr, Vec<u8>)>,
}

pub struct ServerMut {
    /*TODO: pub(crate)*/ pub connected_clients: HashMap<SocketAddr, ConnectedClientMut>,
    pub(crate) clients_to_auth_receiver: crossbeam::Receiver<(SocketAddr, Vec<u8>)>,
}

pub async fn bind<A: ToSocketAddrs>(
    addr: A,
    packet_registry: Arc<PacketRegistry>,
) -> io::Result<(Arc<ServerRead>, Arc<RwLock<ServerShared>>, ServerMut)> {
    let socket = Socket::bind(addr).await?;
    let (clients_to_auth_sender, clients_to_auth_receiver) = crossbeam::unbounded();
    Ok((
        Arc::new(ServerRead {
            socket,
            packet_registry,
        }),
        Arc::new(RwLock::new(ServerShared {
            connected_clients: HashMap::new(),
            clients_to_auth_sender,
        })),
        ServerMut {
            connected_clients: HashMap::new(),
            clients_to_auth_receiver,
        },
    ))
}

pub fn tick(
    server_read: Arc<ServerRead>,
    server_shared: Arc<RwLock<ServerShared>>,
    server_mut: &mut ServerMut,
    runtime: Arc<Runtime>,
) -> HashMap<SocketAddr, Vec<DeserializedPacket>> {
    println!(
        "ticking for {:?} clients, time: {:?}",
        server_mut.connected_clients.len(),
        Instant::now(),
    );
    let now = Instant::now();
    let mut to_disconnect: Vec<SocketAddr> = Vec::new();
    let mut clients_packets_to_process: HashMap<SocketAddr, Vec<DeserializedPacket>> =
        HashMap::new();
    for (addr, connected_client) in server_mut.connected_clients.iter_mut() {
        if let Ok((cache_index, packets_to_process)) =
            connected_client.received_packets_receiver.try_recv()
        {
            if connected_client.pending_packets_confirmation.is_empty() {
                //TODO: that should never happen?
                println!("    client sent a message, but it is not authorized yet");
            } else {
                let (serialized_cache_index, _) = connected_client
                    .pending_packets_confirmation
                    .get(0)
                    .unwrap();

                if *serialized_cache_index == cache_index {
                    connected_client.last_response = Instant::now();
                    connected_client.pending_packets_confirmation.remove(0);

                    if let Some((serialized_cache_index, packets)) =
                        connected_client.pending_packets_confirmation.get(0)
                    {
                        let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
                        buf.push(*serialized_cache_index);
                        buf.extend(&packets.bytes);
                        println!(
                            "  trying resent packet that the client did not confirmed, size: {:?}",
                            buf.len()
                        );
                        let s1 = Arc::clone(&server_read);
                        let addr1 = addr.clone();
                        runtime.spawn(async move {
                            s1.socket
                                .send_to(&buf, addr1)
                                .await
                                .expect("failed to send message in async");
                        });
                    }

                    clients_packets_to_process.insert(addr.clone(), packets_to_process);
                } else {
                    println!("    client sent a message, but there is no concurrency");
                }
            }
        } else {
            if now - connected_client.last_response >= TIMEOUT {
                println!("  client timeout: {:?}, disconnecting...", addr);
                to_disconnect.push(*addr);
                continue;
            } else {
                if let Some((serialized_cache_index, packets)) =
                    connected_client.pending_packets_confirmation.get(0)
                {
                    let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
                    buf.push(*serialized_cache_index);
                    buf.extend(&packets.bytes);
                    println!("  client packet loss: {:?}, resending...", addr);
                    let s1 = Arc::clone(&server_read);
                    let addr1 = addr.clone();
                    runtime.spawn(async move {
                        s1.socket
                            .send_to(&buf, addr1)
                            .await
                            .expect("failed to send message in async");
                    });
                } else {
                    //TODO: that should never happen?
                    println!("    client packet loss but... there is no packet to send back");
                }
            }
        }

        {
            connected_client.last_serialized_cache_index =
                connected_client.last_serialized_cache_index.wrapping_add(1);
            let cache_index = connected_client.last_serialized_cache_index;
            let packets = SerializedPacketList::create(std::mem::replace(
                &mut connected_client.tick_packet_store,
                Vec::new(),
            ));
            if connected_client.pending_packets_confirmation.is_empty() {
                let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
                buf.push(cache_index);
                buf.extend(&packets.bytes);
                connected_client
                    .pending_packets_confirmation
                    .push((cache_index, packets));
                println!(
                    "  sending packet to client, and caching it to handle packet loss, size: {:?}",
                    buf.len()
                );
                let s1 = Arc::clone(&server_read);
                let addr1 = addr.clone();
                runtime.spawn(async move {
                    s1.socket
                        .send_to(&buf, addr1)
                        .await
                        .expect("failed to send message in async");
                });
            } else {
                println!("  caching a packet, since the client has packets to response");
                connected_client
                    .pending_packets_confirmation
                    .push((cache_index, packets));
            }
        }
    }

    let mut server = server_shared.write().unwrap();
    for addr in to_disconnect {
        server_mut.connected_clients.remove(&addr).unwrap();
        server.connected_clients.remove(&addr).unwrap();
    }

    while let Ok((addr, buf)) = server_mut.clients_to_auth_receiver.try_recv() {
        //TODO:
        if buf.len() == 8 {
            let (received_packets_sender, received_packets_receiver) = crossbeam::unbounded();
            server.connected_clients.insert(
                addr,
                ConnectedClientShared {
                    received_packets_sender,
                },
            );
            server_mut.connected_clients.insert(
                addr,
                ConnectedClientMut {
                    last_response: Instant::now(),
                    tick_packet_store: Vec::new(),
                    pending_packets_confirmation: Vec::new(),
                    last_serialized_cache_index: 0,
                    received_packets_receiver,
                },
            );
            println!("    client authenticated successfully");
        } else {
            println!("    client could not send a valid authentication")
        }
    }

    clients_packets_to_process
}

pub async fn pre_read_next_message(
    server_read: &Arc<ServerRead>,
) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 1024];
    let (len, addr) = server_read.socket.recv_from(&mut buf).await?;
    Ok((buf[..len].to_vec(), addr))
}

pub async fn read_next_message(
    server_read: Arc<ServerRead>,
    server_shared: Arc<RwLock<ServerShared>>,
    tuple: (Vec<u8>, SocketAddr),
) {
    let (buf, addr) = tuple;
    println!("received {:?} bytes from {:?}", buf.len(), addr);
    let server_shared = server_shared.read().unwrap();
    if buf.len() == 0 {
        println!("  client sent a empty buf, ignoring it")
    } else if let Some(connected_client_shared) = server_shared.connected_clients.get(&addr) {
        println!("  client already authenticated");

        let cache_index: u8 = u8::from_be_bytes([buf[0]]);
        let received_packets = SerializedPacketList {
            bytes: buf[1..].to_vec(),
        };

        match DeserializedPacket::deserialize(&received_packets.bytes, &server_read.packet_registry)
        {
            Ok(received_packets) => {
                if let Err(e) = connected_client_shared
                    .received_packets_sender
                    .send((cache_index, received_packets))
                {
                    println!("failed to send deserialized packet to channel: {}", e);
                }
            }
            Err(e) => {
                println!("failed to deserialize packets of {:?}, cause: {}", addr, e);
            }
        }
    } else {
        println!("  client is not authenticated...");
        if let Err(e) = server_shared.clients_to_auth_sender.send((addr, buf)) {
            println!("failed to send auth packet to channel: {}", e);
        }
    }
}

pub fn add_read_handler(
    server_read: Arc<ServerRead>,
    server_shared: Arc<RwLock<ServerShared>>,
    read_handler_props: Arc<ReadHandlerProps>,
    runtime: Arc<Runtime>,
) {
    Arc::clone(&runtime).spawn(async move {
        let mut was_used = false;
        *read_handler_props.surplus_count.lock().await += 1;
        println!(
            "read handler added, actual size: {:?}",
            *read_handler_props.surplus_count.lock().await
        );
        loop {
            if *read_handler_props.surplus_count.lock().await
                > read_handler_props.surplus_target_size + 1
            {
                let mut surplus_count = read_handler_props.surplus_count.lock().await;
                if !was_used {
                    *surplus_count -= 1;
                }
                println!("read handler was removed, actual size: {:?}", surplus_count);
                break;
            } else {
                match timeout(
                    read_handler_props.surplus_timeout,
                    pre_read_next_message(&server_read),
                )
                .await
                {
                    Ok(tuple) => {
                        let tuple = tuple.unwrap();
                        {
                            let mut rng = thread_rng();
                            if rng.gen_bool(0.1) {
                                println!("  packets received from {:?}: {:?}, but a packet loss will be simulated", 
                                    tuple.1, tuple.0.len());
                                continue;
                            }
                        }

                        if !was_used {
                            was_used = true;
                            let mut surplus_count = read_handler_props.surplus_count.lock().await;
                            *surplus_count -= 1;
                        }
                        read_next_message(
                            Arc::clone(&server_read),
                            Arc::clone(&server_shared),
                            tuple,
                        )
                        .await;
                        println!();
                    }
                    Err(_) => {
                        if was_used {
                            was_used = false;
                            let mut surplus_count = read_handler_props.surplus_count.lock().await;
                            *surplus_count += 1;
                        }
                    }
                }
            }
        }
    });
}

pub struct ConnectedClientShared {
    pub(crate) received_packets_sender: crossbeam::Sender<(u8, Vec<DeserializedPacket>)>,
}

pub struct ConnectedClientMut {
    pub(crate) last_response: Instant,
    pub(crate) tick_packet_store: Vec<SerializedPacket>,
    pub(crate) pending_packets_confirmation: Vec<(u8, SerializedPacketList)>,
    pub(crate) last_serialized_cache_index: u8,
    pub(crate) received_packets_receiver: crossbeam::Receiver<(u8, Vec<DeserializedPacket>)>,
}

impl ConnectedClientMut {
    pub fn send<P: Packet>(&mut self, server_read: &ServerRead, packet: &P) -> io::Result<()> {
        let serialized = server_read.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&mut self, serialized_packet: SerializedPacket) {
        self.tick_packet_store.push(serialized_packet);
    }
}

pub struct ReadHandlerProps {
    // number of asynchronous tasks that must be slacking when receiving packets
    pub surplus_target_size: u16,
    pub surplus_timeout: Duration,
    pub surplus_count: Arc<tokio::sync::Mutex<u16>>,
}

impl Default for ReadHandlerProps {
    fn default() -> Self {
        ReadHandlerProps {
            surplus_target_size: 5u16,
            surplus_timeout: Duration::from_secs(15),
            surplus_count: Arc::new(tokio::sync::Mutex::new(0u16)),
        }
    }
}
