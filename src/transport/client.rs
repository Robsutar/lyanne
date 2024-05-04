use super::Socket;
use std::io;
use tokio::net::ToSocketAddrs;

pub struct Client {
    pub(crate) socket: Socket,
}

impl Client {
    pub async fn connect<A: ToSocketAddrs>(remote_addr: A) -> io::Result<Client> {
        let socket = Socket::bind("0.0.0.0:0").await?;
        socket.connect(remote_addr).await?;

        Ok(Self { socket })
    }

    pub async fn tick(&mut self) -> io::Result<()> {
        let len = self.socket.send("Auth me!".as_bytes()).await?;
        println!("{:?} bytes sent", len);
        Ok(())
    }
}
