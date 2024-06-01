use crate::{
    packets::{DeserializedPacket, Packet, PacketRegistry, SerializedPacket, SerializedPacketList},
    transport::MAX_PENDING_MESSAGES_STACK,
};
use crossbeam_channel as crossbeam;

use super::Socket;
use rand::{thread_rng, Rng};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::Arc,
    time::Instant,
};
use tokio::{net::ToSocketAddrs, runtime::Runtime};

pub struct ClientRead {
    pub(crate) socket: Socket,
    /*TODO: pub(crate)*/ pub packet_registry: Arc<PacketRegistry>,
    /*TODO: pub(crate)*/ pub connected_server: ConnectedServerShared,
}

pub struct ClientMut {
    /*TODO: pub(crate)*/ pub connected_server: ConnectedServerMut,
}

pub async fn connect<A: ToSocketAddrs>(
    remote_addr: A,
    packet_registry: Arc<PacketRegistry>,
) -> io::Result<(Arc<ClientRead>, ClientMut)> {
    let socket = Socket::bind("0.0.0.0:0").await?;
    socket.connect(remote_addr).await?;
    let len = socket.send("Auth me!".as_bytes()).await?;
    println!("{:?} bytes sent (for authentication)", len);

    let (received_packets_sender, received_packets_receiver) = crossbeam::unbounded();

    let client_read = Arc::new(ClientRead {
        socket,
        packet_registry,
        connected_server: ConnectedServerShared {
            received_packets_sender,
        },
    });

    Ok((
        client_read,
        ClientMut {
            connected_server: ConnectedServerMut {
                last_response: Instant::now(),
                tick_packet_store: Vec::new(),
                stored_packets_confirmation: vec![
                    (0u8, SerializedPacketList { bytes: Vec::new() });
                    MAX_PENDING_MESSAGES_STACK
                ],
                received_packets_receiver,
            },
        },
    ))
}

pub fn tick(
    client_read: Arc<ClientRead>,
    client_mut: &mut ClientMut,
    runtime: Arc<Runtime>,
) -> io::Result<Vec<DeserializedPacket>> {
    let connected_server = &mut client_mut.connected_server;
    if let Ok((cache_index, received_packets)) =
        connected_server.received_packets_receiver.try_recv()
    {
        println!("ticking for server");

        if cache_index
            == connected_server
                .stored_packets_confirmation
                .last()
                .unwrap()
                .0
                .wrapping_add(1)
        {
            println!("server sent a new tick, cache_index: {:?}", cache_index);

            let connected_server = &mut client_mut.connected_server;

            let packets = SerializedPacketList::create(std::mem::replace(
                &mut connected_server.tick_packet_store,
                Vec::new(),
            ));

            let mut buf: Vec<u8> = Vec::with_capacity(1 + &packets.bytes.len());
            buf.push(cache_index);
            buf.extend(&packets.bytes);

            connected_server.last_response = Instant::now();
            connected_server.stored_packets_confirmation.remove(0);
            connected_server
                .stored_packets_confirmation
                .push((cache_index, packets));

            {
                let s1 = Arc::clone(&client_read);
                runtime.spawn(async move {
                    s1.socket
                        .send(&buf)
                        .await
                        .expect("failed to send message in async");
                });
            }

            return Ok(received_packets);
        } else {
            for (stored_cache_index, packets) in
                connected_server.stored_packets_confirmation.iter().rev()
            {
                if *stored_cache_index == cache_index {
                    println!("server packet loss, resending packet {:?}...", cache_index);
                    let buf = packets.bytes.clone();

                    let s1 = Arc::clone(&client_read);
                    runtime.spawn(async move {
                        s1.socket
                            .send(&buf)
                            .await
                            .expect("failed to send message in async");
                    });

                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "server packet loss",
                    ));
                }
            }

            println!("server sent a packet, but the cache_index was not found, ignoring it");

            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server invalid packet loss",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "server sent nothing",
    ))
}

pub async fn pre_read_next_message(client_read: &Arc<ClientRead>) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1024];
    let len = client_read.socket.recv(&mut buf).await?;
    Ok(buf[..len].to_vec())
}

pub async fn read_next_message(client_read: Arc<ClientRead>, buf: Vec<u8>) {
    println!("received {:?} bytes from server", buf.len());

    if buf.len() == 0 {
        println!("  server sent a empty buf, ignoring it")
    } else {
        let cache_index: u8 = u8::from_be_bytes([buf[0]]);
        let received_packets = SerializedPacketList {
            bytes: buf[1..].to_vec(),
        };

        match DeserializedPacket::deserialize(&received_packets.bytes, &client_read.packet_registry)
        {
            Ok(received_packets) => {
                if let Err(e) = client_read
                    .connected_server
                    .received_packets_sender
                    .send((cache_index, received_packets))
                {
                    println!("failed to send deserialized packet to channel: {}", e);
                }
            }
            Err(e) => {
                println!("failed to deserialize packets of server, cause: {}", e);
            }
        }
    }
}

pub struct ConnectedServerShared {
    pub(crate) received_packets_sender: crossbeam::Sender<(u8, Vec<DeserializedPacket>)>,
}

pub struct ConnectedServerMut {
    pub(crate) last_response: Instant,
    pub(crate) tick_packet_store: Vec<SerializedPacket>,
    // size should be equals to MAX_PENDING_MESSAGES_STACK
    pub(crate) stored_packets_confirmation: Vec<(u8, SerializedPacketList)>,
    pub received_packets_receiver: crossbeam::Receiver<(u8, Vec<DeserializedPacket>)>,
}

impl ConnectedServerMut {
    pub fn send<P: Packet>(&mut self, client: &ClientRead, packet: &P) -> io::Result<()> {
        let serialized = client.packet_registry.serialize(packet)?;
        self.send_packet_serialized(serialized);
        Ok(())
    }
    pub fn send_packet_serialized(&mut self, serialized_packet: SerializedPacket) {
        self.tick_packet_store.push(serialized_packet);
    }
}
