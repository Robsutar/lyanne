use lyanne::{packets::BarPacket, transport::client};
use std::{io, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::timeout};

#[tokio::main]
async fn main() -> io::Result<()> {
    let tick_timeout = Duration::from_secs(10);

    let (client, client_mut) = client::connect("127.0.0.1:8080").await?;
    let client_mut = Arc::new(Mutex::new(client_mut));
    println!("client connected");

    let handler = tokio::spawn({
        let client = Arc::clone(&client);
        let client_mut = Arc::clone(&client_mut);
        async move {
            loop {
                println!("trying receive...");
                let task = client::pre_read_next_message(&client);
                match timeout(tick_timeout, task).await {
                    Ok(tuple) => {
                        let mut client_mut = client_mut.lock().await;
                        client::read_next_message(&client, &mut client_mut, tuple.unwrap())
                            .await
                            .expect("failed to read next message");
                        println!();

                        let message = format!("Random str: {:?}", 12);
                        let packet = BarPacket { message };
                        client_mut.connected_server.send(&packet).unwrap();
                    }
                    Err(_) => {
                        println!("server tick timeout, aborting connection...");
                        break;
                    }
                }
            }
        }
    });

    let _ = tokio::try_join!(handler);

    Ok(())
}
