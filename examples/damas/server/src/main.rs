use lyanne::{
    packets::FooPacket,
    transport::server::{self, Server, ServerMut},
};
use rand::{thread_rng, Rng};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    sync::Mutex,
    time::{self, timeout},
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let surplus_target_size = 5u16; // number of asynchronous tasks that must be slacking when receiving packets
    let surplus_timeout = Duration::from_secs(15);
    let surplus_count = Arc::new(Mutex::new(0u16));

    let (server, server_mut) = server::bind("127.0.0.1:8080").await?;
    let server_mut = Arc::new(Mutex::new(server_mut));
    println!("server open");

    for _ in 0..surplus_target_size {
        add_read_handler(
            Arc::clone(&server),
            Arc::clone(&server_mut),
            Arc::clone(&surplus_count),
            surplus_target_size.clone(),
            surplus_timeout.clone(),
        );
    }

    let ticker = tokio::spawn({
        let a_server = Arc::clone(&server);
        let a_server_mut = Arc::clone(&server_mut);
        async move {
            println!("starting server tick");
            let mut interval = time::interval(Duration::from_millis(1000));
            loop {
                println!("waiting interval...");
                interval.tick().await;
                let mut server_mut = a_server_mut.lock().await;
                println!("sending(storing) some random packets");
                for (_, connected_client) in server_mut.connected_clients.iter_mut() {
                    let mut rng = thread_rng();
                    for _ in 0..rng.gen_range(0..2) {
                        let message = format!("Random str: {:?}", rng.gen::<i32>());
                        let packet = FooPacket { message };
                        connected_client.send(&packet).unwrap();
                    }
                }
                server::tick(&a_server, &mut server_mut)
                    .await
                    .expect("failed to server tick");

                if *surplus_count.lock().await < surplus_target_size - 1 {
                    add_read_handler(
                        Arc::clone(&a_server),
                        Arc::clone(&a_server_mut),
                        Arc::clone(&surplus_count),
                        surplus_target_size.clone(),
                        surplus_timeout.clone(),
                    );
                }
            }
        }
    });

    let _ = tokio::try_join!(ticker);

    Ok(())
}

fn add_read_handler(
    server: Arc<Server>,
    server_mut: Arc<Mutex<ServerMut>>,
    surplus_count: Arc<Mutex<u16>>,
    surplus_target_size: u16,
    surplus_timeout: Duration,
) {
    tokio::spawn(async move {
        let mut was_used = false;
        *surplus_count.lock().await += 1;
        println!(
            "read handler added, actual size: {:?}",
            *surplus_count.lock().await
        );
        loop {
            if *surplus_count.lock().await > surplus_target_size + 1 {
                let mut surplus_count = surplus_count.lock().await;
                if !was_used {
                    *surplus_count -= 1;
                }
                println!("read handler was removed, actual size: {:?}", surplus_count);
                break;
            } else {
                let task = server::pre_read_next_message(&server);
                match timeout(surplus_timeout, task).await {
                    Ok(tuple) => {
                        if !was_used {
                            was_used = true;
                            let mut surplus_count = surplus_count.lock().await;
                            *surplus_count -= 1;
                        }
                        let mut server_mut = server_mut.lock().await;
                        server::read_next_message(&server, &mut server_mut, tuple.unwrap())
                            .await
                            .expect("failed to read next message");
                        println!();
                    }
                    Err(_) => {
                        if was_used {
                            was_used = false;
                            let mut surplus_count = surplus_count.lock().await;
                            *surplus_count += 1;
                        }
                    }
                }
            }
        }
    });
}
