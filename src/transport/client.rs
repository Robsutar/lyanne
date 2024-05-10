use crate::packets::{Packet, PacketRegistry, SerializedPacket, SerializedPacketList};

use super::{EventReceiver, Socket};
use std::{io, sync::Arc, time::Instant};
use tokio::net::ToSocketAddrs;

pub struct Client {
    pub(crate) socket: Socket,
}

pub struct ClientMut {
    /*TODO: pub(crate)*/ pub connected_server: ConnectedServer,
    event_receiver: EventReceiver,
}

pub async fn connect<A: ToSocketAddrs>(remote_addr: A) -> io::Result<(Client, ClientMut)> {
    let socket = Socket::bind("0.0.0.0:0").await?;
    socket.connect(remote_addr).await?;
    let len = socket.send("Auth me!".as_bytes()).await?;
    println!("{:?} bytes sent (for authentication)", len);

    let client = Arc::new(Client {
        socket,
        packet_registry: PacketRegistry::new(),
    });

    let client_clone = client.clone();
        ClientMut {
            connected_server: ConnectedServer {
                last_response: Instant::now(),
                tick_packet_store: Vec::new(),
                last_sent_packets: (0, SerializedPacketList { bytes: Vec::new() }),
            },
            event_receiver: EventReceiver {},
        },
    ))
}

pub async fn tick(
    client: &Arc<Client>,
    client_mut: &mut ClientMut,
    serialized_cache_index: u8,
    packets: SerializedPacketList,
) -> io::Result<()> {
    println!("ticking for connected server");
    let packet_registry = PacketRegistry::new(); //TODO
    let mut packets_to_process: Vec<SerializedPacket> = Vec::new();
    let connected_server = &mut client_mut.connected_server;

    let mut packet_buf_index = 0;
    let buf = &packets.bytes;
    loop {
        if buf.len() == packet_buf_index {
            break;
        }

        if let Ok(serialized_packet) = SerializedPacket::read_first(buf, packet_buf_index) {
            packet_buf_index += serialized_packet.bytes.len();
            packets_to_process.push(serialized_packet);
        } else if let Err(e) = SerializedPacket::read_first(buf, packet_buf_index) {
            println!(
                "server sent a invalid packet: {}, cancelling all iteration",
                e
            );
            break;
        }
    }

    for serialized_packet in packets_to_process {
        let (_, deserialize, call) = packet_registry
            .packet_map
            .get(&serialized_packet.packet_id)
            .expect(&format!(
                "packet not found: {:?}",
                serialized_packet.packet_id
            ));
        if let Ok(deserialized) = deserialize(&serialized_packet.bytes[4..]) {
            call(&mut client_mut.event_receiver, deserialized);
        } else {
            println!("failed to deserialize a packet of server, cancelling all iteration",);
            break;
        }
    }

    let packets = SerializedPacketList::create(std::mem::replace(
        &mut connected_server.tick_packet_store,
        Vec::new(),
    ));

    let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
    buf.push(serialized_cache_index);
    buf.extend(&packets.bytes);

    connected_server.last_response = Instant::now();
    connected_server.last_sent_packets = (serialized_cache_index, packets);

    let s1 = client.clone();
    tokio::task::spawn(async move {
        s1.socket
            .send(&buf)
            .await
            .expect("failed to send message in async");
    });
    Ok(())
}

pub async fn pre_read_next_message(client: &Arc<Client>) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1024];
    let len = client.socket.recv(&mut buf).await?;
    Ok(buf[..len].to_vec())
}

pub async fn read_next_message(
    client: &Arc<Client>,
    client_mut: &mut ClientMut,
    buf: Vec<u8>,
) -> io::Result<()> {
    println!("received {:?} bytes from server", buf.len());
    let connected_server = &mut client_mut.connected_server;
    let cache_index = u8::from_be_bytes([buf[0]]);
    if cache_index == connected_server.last_sent_packets.0 {
        //Server has loosed last sent packet, so, the client will interpret it as a packet loss, and resend the cached value
        println!("server packet loss, resending last packet...");
        let buf = connected_server.last_sent_packets.1.bytes.clone();
        let s1 = client.clone();
        tokio::task::spawn(async move {
            s1.socket
                .send(&buf)
                .await
                .expect("failed to send message in async");
        });
    } else {
        println!("server sent a new tick, cache_index: {:?}", cache_index);

        tick(
            client,
            client_mut,
            cache_index,
            SerializedPacketList {
                bytes: buf[1..].to_vec(),
            },
        )
        .await?;
    }
    Ok(())
}

pub struct ConnectedServer {
    pub(crate) last_response: Instant,
    pub(crate) tick_packet_store: Vec<SerializedPacket>,
    pub(crate) last_sent_packets: (u8, SerializedPacketList),
}

impl ConnectedServer {
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
