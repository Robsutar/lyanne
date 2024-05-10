use tokio::net::ToSocketAddrs;

use crate::packets::{Packet, PacketRegistry, SerializedPacket, SerializedPacketList};

use super::{EventReceiver, Socket};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(10);
const INTERPRET_AS_PACKET_LOSS: Duration = Duration::from_secs(2);

pub struct Server {
    pub(crate) socket: Socket,
}

pub struct ServerMut {
    /*TODO: pub(crate)*/ pub connected_clients: HashMap<SocketAddr, ConnectedClient>,
    event_receiver: EventReceiver,
}

pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<(Server, ServerMut)> {
    let socket = Socket::bind(addr).await?;
    Ok((
        Server { socket },
        ServerMut {
            connected_clients: HashMap::new(),
            event_receiver: EventReceiver {},
        },
    ))
}

pub async fn tick(server: &Arc<Server>, server_mut: &mut ServerMut) -> io::Result<()> {
    println!(
        "ticking for {:?} clients",
        server_mut.connected_clients.len()
    );
    let packet_registry = PacketRegistry::new(); //TODO
    let now = Instant::now();
    let mut to_disconnect: Vec<SocketAddr> = Vec::new();
    let mut clients_packets_to_process: HashMap<SocketAddr, Vec<SerializedPacket>> = HashMap::new();
    for (addr, connected_client) in server_mut.connected_clients.iter_mut() {
        if now - connected_client.last_response >= TIMEOUT {
            println!("  client timeout: {:?}, disconnecting...", addr);
            to_disconnect.push(*addr);
            continue;
        } else if now - connected_client.last_response >= INTERPRET_AS_PACKET_LOSS {
            if let Some((serialized_cache_index, packets)) =
                connected_client.pending_packets_confirmation.get(0)
            {
                let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
                buf.push(*serialized_cache_index);
                buf.extend(&packets.bytes);
                println!("  client packet loss: {:?}, resending...", addr);
                let s1 = server.clone();
                let addr1 = addr.clone();
                tokio::task::spawn(async move {
                    s1.socket
                        .send_to(&buf, addr1)
                        .await
                        .expect("failed to send message in async");
                });
            } else {
                todo!("")
            }
        } else {
            connected_client.last_serialized_cache_index += 1;
            let serialized_cache_index = connected_client.last_serialized_cache_index;
            let packets = SerializedPacketList::create(std::mem::replace(
                &mut connected_client.tick_packet_store,
                Vec::new(),
            ));
            if connected_client.pending_packets_confirmation.is_empty() {
                let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
                buf.push(serialized_cache_index);
                buf.extend(&packets.bytes);
                connected_client
                    .pending_packets_confirmation
                    .push((serialized_cache_index, packets));
                println!(
                    "  sending packet to client, and caching it to handle packet loss, size: {:?}",
                    buf.len()
                );
                let s1 = server.clone();
                let addr1 = addr.clone();
                tokio::task::spawn(async move {
                    s1.socket
                        .send_to(&buf, addr1)
                        .await
                        .expect("failed to send message in async");
                });
            } else {
                println!("  caching a packet, since the client did not response yet");
                connected_client
                    .pending_packets_confirmation
                    .push((serialized_cache_index, packets));
            }
        }
        let mut packets_to_process: Vec<SerializedPacket> = Vec::new();

        for packets in connected_client.cached_received_packets.iter() {
            let mut packet_buf_index = 0;
            let buf = &packets.bytes;
            loop {
                if buf.len() == packet_buf_index {
                    break;
                }

                if let Ok(serialized_packet) = SerializedPacket::read_first(buf, packet_buf_index) {
                    packet_buf_index += serialized_packet.bytes.len();
                    packets_to_process.push(serialized_packet);
                } else {
                    println!(
                        "client {:?} sent a invalid packet, cancelling all iteration",
                        addr
                    );
                    break;
                }
            }
        }
        clients_packets_to_process.insert(addr.clone(), packets_to_process);
    }
    for addr in to_disconnect {
        server_mut.connected_clients.remove(&addr).unwrap();
    }
    for connected_client in server_mut.connected_clients.values_mut() {
        connected_client.cached_received_packets.clear();
    }

    for (addr, packets_to_process) in clients_packets_to_process {
        for serialized_packet in packets_to_process {
            let (_, deserialize, call) = packet_registry
                .packet_map
                .get(&serialized_packet.packet_id)
                .unwrap();
            if let Ok(deserialized) = deserialize(&serialized_packet.bytes[4..]) {
                call(&mut server_mut.event_receiver, deserialized);
            } else {
                println!(
                    "failed to deserialize a packet of {:?}, cancelling all iteration",
                    addr
                );
                break;
            }
        }
    }
    Ok(())
}

pub async fn pre_read_next_message(server: &Arc<Server>) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 1024];
    let (len, addr) = server.socket.recv_from(&mut buf).await?;
    Ok((buf[..len].to_vec(), addr))
}

pub async fn read_next_message(
    server: &Arc<Server>,
    server_mut: &mut ServerMut,
    tuple: (Vec<u8>, SocketAddr),
) -> io::Result<()> {
    let (buf, addr) = tuple;
    println!("received {:?} bytes from {:?}", buf.len(), addr);
    if let Some(connected_client) = server_mut.connected_clients.get_mut(&addr) {
        println!("  client already authenticated");
        if connected_client.pending_packets_confirmation.is_empty() {
            println!("    client sent a message, but it is not authorized yet");
        } else {
            println!(
                "    client sent a message back... {:?}",
                connected_client.last_response
            );
            connected_client.last_response = Instant::now();
            let (serialized_cache_index, _) = connected_client
                .pending_packets_confirmation
                .get(0)
                .unwrap();
            let cache_index = u8::from_be_bytes([buf[0]]);
            if *serialized_cache_index == cache_index {
                connected_client.pending_packets_confirmation.remove(0);
                let received_packets = SerializedPacketList {
                    bytes: buf[1..].to_vec(),
                };
                connected_client
                    .cached_received_packets
                    .push(received_packets);
                if let Some((_, packets)) = connected_client.pending_packets_confirmation.get(0) {
                    let buf = packets.bytes.clone();
                    let s1 = server.clone();
                    let addr1 = addr.clone();
                    tokio::task::spawn(async move {
                        s1.socket
                            .send_to(&buf, addr1)
                            .await
                            .expect("failed to send message in async");
                    });
                }
            } else {
                println!("    client sent a message, but there is no concurrency");
            }
        }
    } else {
        println!("  client is not authenticated...");
        if buf.len() == 8 {
            server_mut.connected_clients.insert(
                addr,
                ConnectedClient {
                    last_response: Instant::now(),
                    tick_packet_store: Vec::new(),
                    pending_packets_confirmation: Vec::new(),
                    last_serialized_cache_index: 0,
                    cached_received_packets: Vec::new(),
                },
            );
            println!("    client authenticated successfully");
        } else {
            println!("    client could not send a valid authentication")
        }
    }
    Ok(())
}

pub struct ConnectedClient {
    pub(crate) last_response: Instant,
    pub(crate) tick_packet_store: Vec<SerializedPacket>,
    pub(crate) pending_packets_confirmation: Vec<(u8, SerializedPacketList)>,
    pub(crate) last_serialized_cache_index: u8,
    pub(crate) cached_received_packets: Vec<SerializedPacketList>,
}

impl ConnectedClient {
    pub fn send<P: Packet>(&mut self, packet: &P) -> io::Result<()> {
        let packet_registry = PacketRegistry::new(); //TODO
        let serialized = packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&mut self, serialized_packet: SerializedPacket) {
        self.tick_packet_store.push(serialized_packet);
    }
}
