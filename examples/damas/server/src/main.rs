use lyanne::transport::server::*;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut server = Server::bind("127.0.0.1:8080").await?;
    println!("server open");
    loop {
        println!("trying receive...");

        server.tick().await?;

        println!();
    }
}
