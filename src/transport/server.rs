use tokio::net::ToSocketAddrs;

use super::{ClientIdentifier, Socket};
use std::{collections::HashMap, io};

pub struct Server {
    pub(crate) socket: Socket,
    pub(crate) connected_clients: HashMap<ClientIdentifier, ConnectedClient>,
    pub(crate) buf: [u8; 1024],
}

impl Server {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Server> {
        let socket = Socket::bind(addr).await?;
        Ok(Self {
            socket,
            connected_clients: HashMap::new(),
            buf: [0; 1024],
        })
    }

    pub async fn tick(&mut self) -> io::Result<()> {
        let (len, addr) = self.socket.recv_from(&mut self.buf).await?;
        println!("received {:?} bytes from {:?}", len, addr);
        Ok(())
    }
}

pub struct ConnectedClient {
    pub addr: String,
}

impl ConnectedClient {}
