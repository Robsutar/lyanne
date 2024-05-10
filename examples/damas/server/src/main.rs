use lyanne::{
    packets::FooPacket,
    transport::server::{self},
};
use std::{io, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time};

#[tokio::main]
async fn main() -> io::Result<()> {
    let (server, server_mut) = server::bind("127.0.0.1:8080").await?;
    let server_mut = Arc::new(Mutex::new(server_mut));
    println!("server open");

    let handler = tokio::spawn({
        let server = Arc::clone(&server);
        let server_mut = Arc::clone(&server_mut);
        async move {
            loop {
                println!("trying receive...");
                let tuple = server::pre_read_next_message(&server).await.unwrap();
                let mut server_mut = server_mut.lock().await;
                server::read_next_message(&server, &mut server_mut, tuple)
                    .await
                    .expect("failed to read next message");
                println!();
            }
        }
    });

    let ticker = tokio::spawn({
        let server = Arc::clone(&server);
        let server_mut = Arc::clone(&server_mut);
        async move {
            println!("starting server tick");
            let mut interval = time::interval(Duration::from_millis(1000));
            loop {
                println!("waiting interval...");
                interval.tick().await;
                let mut server_mut = server_mut.lock().await;
                println!("sending(storing) some random packets");
                for (_, connected_client) in server_mut.connected_clients.iter_mut() {
                    let message = format!("Random str: {:?}", 44);
                    let packet = FooPacket { message };
                    connected_client.send(&packet).unwrap();

                    let message = format!("Random str: {:?}", 33232);
                    let packet = FooPacket { message };
                    connected_client.send(&packet).unwrap();
                }
                server::tick(&server, &mut server_mut)
                    .await
                    .expect("failed to server tick");
            }
        }
    });

    let _ = tokio::try_join!(handler, ticker);

    Ok(())
}
