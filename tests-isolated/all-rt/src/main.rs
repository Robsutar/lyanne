use std::{error::Error, time::Duration};

pub mod client;
pub mod error;
pub mod packets;
pub mod server;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const SERVER_TICK_DELAY: Duration = Duration::from_millis(50);

pub const CLIENT_NAME: &'static str = "Josh";
pub const SERVER_NAME: &'static str = "Server";
pub const SERVER_TO_CLIENT_MESSAGE: &'static str = "success: true";
pub const CLIENT_TO_SERVER_MESSAGE: &'static str = "true: success";
pub const SERVER_DISCONNECT_INFO: &'static str = "all: done";

fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");
    smol::block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn Error>> {
    let server = server::create().await?;
    let server_handle = smol::spawn(server::start_tick_cycle(server));

    let client = client::create().await?;
    let client_handle = smol::spawn(client::start_tick_cycle(client));

    server_handle.await.unwrap();
    client_handle.await.unwrap();

    Ok(())
}
