use tokio::net::ToSocketAddrs;

use crate::packets::{Packet, SerializedPackets};

use super::Socket;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(10);
const INTERPRET_AS_PACKET_LOSS: Duration = Duration::from_secs(2);

pub struct Server {
    pub(crate) socket: Socket,
}

pub struct ServerMut {
    pub(crate) connected_clients: HashMap<SocketAddr, ConnectedClient>,
}

pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<(Server, ServerMut)> {
    let socket = Socket::bind(addr).await?;
    Ok((
        Server { socket },
        ServerMut {
            connected_clients: HashMap::new(),
        },
    ))
}

pub async fn tick(server: &Arc<Server>, server_mut: &mut ServerMut) -> io::Result<()> {
    let now = Instant::now();
    let mut to_disconnect: Vec<SocketAddr> = Vec::new();
    println!(
        "ticking for {:?} clients",
        server_mut.connected_clients.len()
    );
    for (addr, connected_client) in server_mut.connected_clients.iter_mut() {
        if now - connected_client.last_response >= TIMEOUT {
            println!("  client timeout: {:?}, disconnecting...", addr);
            to_disconnect.push(*addr);
        } else if now - connected_client.last_response >= INTERPRET_AS_PACKET_LOSS {
            if let Some(packets) = connected_client.pending_packets_confirmation.get(0) {
                let buff = packets.as_buff();
                println!("  client packet loss: {:?}, resending...", addr);
                let s1 = server.clone();
                let addr1 = addr.clone();
                tokio::task::spawn(async move {
                    s1.socket
                        .send_to(&buff, addr1)
                        .await
                        .expect("failed to send message in async");
                });
            } else {
                todo!("")
            }
        } else {
            let packets = Packet::serialize_list(&connected_client.tick_packet_store);
            connected_client.tick_packet_store.clear();
            if connected_client.pending_packets_confirmation.is_empty() {
                let buff = packets.as_buff();
                connected_client.pending_packets_confirmation.push(packets);
                println!("  sending packet to client, and caching it to handle packet loss");
                let s1 = server.clone();
                let addr1 = addr.clone();
                tokio::task::spawn(async move {
                    s1.socket
                        .send_to(&buff, addr1)
                        .await
                        .expect("failed to send message in async");
                });
            } else {
                println!("  caching a packet, since the client did not response yet");
                connected_client.pending_packets_confirmation.push(packets);
            }
        }
    }
    for addr in to_disconnect {
        server_mut.connected_clients.remove(&addr).unwrap();
    }
    Ok(())
}

pub async fn pre_read_next_message(
    server: &Arc<Server>,
) -> io::Result<([u8; 1024], usize, SocketAddr)> {
    let mut buf = [0u8; 1024];
    let (len, addr) = server.socket.recv_from(&mut buf).await?;
    Ok((buf, len, addr))
}

pub async fn read_next_message(
    server: &Arc<Server>,
    server_mut: &mut ServerMut,
    tuple: ([u8; 1024], usize, SocketAddr),
) -> io::Result<()> {
    let (buf, len, addr) = tuple;
    println!("received {:?} bytes from {:?}", len, addr);
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
            let removed = connected_client.pending_packets_confirmation.remove(0);
            //TODO: check if [`buf`] are according to [`removed`]
            if removed.size < 732367 {
                process_packet(&server, server_mut, &addr, &buf[..len]).await?;
            } else {
                println!("    client sent a message, but there is no concurrency");
            }
        }
    } else {
        println!("  client is not authenticated...");
        if len == 8 {
            server_mut.connected_clients.insert(
                addr,
                ConnectedClient {
                    addr,
                    last_response: Instant::now(),
                    tick_packet_store: Vec::new(),
                    pending_packets_confirmation: Vec::new(),
                },
            );
            println!("    client authenticated successfully");
        } else {
            println!("    client could not send a valid authentication")
        }
    }
    Ok(())
}

async fn process_packet(
    server: &Arc<Server>,
    server_mut: &mut ServerMut,
    addr: &SocketAddr,
    buf: &[u8],
) -> io::Result<()> {
    println!(
        "processing packet [BEP BEP] {:?} {:?}",
        addr,
        std::str::from_utf8(buf)
    );
    let connected_client = server_mut.connected_clients.get(addr).unwrap();
    if let Some(packets) = connected_client.pending_packets_confirmation.get(0) {
        let buff = packets.as_buff();
        server.socket.send_to(&buff, addr).await?;
    }
    Ok(())
}

pub struct ConnectedClient {
    pub addr: SocketAddr,
    pub(crate) last_response: Instant,
    pub(crate) tick_packet_store: Vec<Packet>,
    pub(crate) pending_packets_confirmation: Vec<SerializedPackets>,
}
