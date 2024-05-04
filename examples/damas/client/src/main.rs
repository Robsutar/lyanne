use lyanne::transport::client::*;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut client = Client::connect("127.0.0.1:8080").await?;
    println!("client connected");
    loop {
        println!("trying send...");

        client.tick().await?;

        println!();
    }
}
