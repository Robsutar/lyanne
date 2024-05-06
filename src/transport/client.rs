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
        let len = socket.send("Auth me!".as_bytes()).await?;
        println!("{:?} bytes sent (for authentication)", len);

        Ok(Self { socket })
    }

    pub async fn tick(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        let len = self.socket.recv(&mut buf).await?;
        let buf = &buf[..len];
        println!(
            "server tick received {:?}, now i can send some accumulated message",
            std::str::from_utf8(buf)
        );
        self.socket.send("Heya!".as_bytes()).await?;
        Ok(())
    }
}
