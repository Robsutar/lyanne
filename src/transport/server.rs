use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;

use crate::{
    collections::OrderedRotatableU8Vec,
    messages::{DeserializedMessage, MessagePart},
    packets::PacketRegistry,
};

/// Read-only properties of the server
///
/// Intended to use used with [`Arc`]
pub struct ServerRead {
    socket: UdpSocket,
    packet_registry: Arc<PacketRegistry>,
}

/// Read-only properties of the server, but mutable at [`tick()`]
///
/// Intended to use used with [`RwLock`]
pub struct ServerTickMut {
    connected_clients: HashMap<SocketAddr, ConnectedClientTickMut>,
    authentications_sender: crossbeam_channel::Sender<(SocketAddr, DeserializedMessage)>,
}

/// Mutable properties of the server
///
/// Not intended to be shared between threads
pub struct ServerMut {
    connected_clients: HashMap<SocketAddr, ConnectedClientMut>,
    authentications_receiver: crossbeam_channel::Receiver<(SocketAddr, DeserializedMessage)>,
}

/// Read-only properties of the connected client, but mutable at [`tick()`]
///
/// Intended to use used inside [`ServerTickMut`]
pub struct ConnectedClientTickMut {
    messages_receiver: crossbeam_channel::Receiver<DeserializedMessage>,
    message_parts_received: OrderedRotatableU8Vec<MessagePart>,
}

/// Mutable properties of the connected client
///
/// Intended to be used inside [`ServerMut`]
pub struct ConnectedClientMut {}
