use lyanne::{client::*, packets::*, *};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{self, AsyncBufReadExt},
    runtime::Handle,
    sync::mpsc,
};
use tokio_chat::packets::*;

#[tokio::main]
async fn main() {
    let (line_sender, mut line_receiver) = mpsc::unbounded_channel();
    let _console_reader_handle = tokio::spawn(console_reader(line_sender));

    println!("Write your nickname:");
    let player_name = line_receiver.recv().await.unwrap();

    let runtime = Handle::current();

    let packet_registry = new_packet_registry();

    let remote_addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography(AuthenticationProperties {
        message: SerializedPacketList::single(
            packet_registry.serialize(&HelloPacket { player_name }),
        ),
        timeout: Duration::from_secs(10),
    });

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
        runtime,
    );

    let connect_result = connect_handle
        .await
        .unwrap()
        .expect("Failed to connect client");

    let client = connect_result.client;

    println!("Client connected to {:?}", remote_addr);

    if let Ok(chat_context) = connect_result
        .initial_message
        .to_packet_list()
        .remove(0)
        .packet
        .downcast::<ChatContextPacket>()
    {
        println!("Connected players: {:?}", chat_context.connected_players);
    } else {
        println!("Server did not sent a chat context in the initial message, finishing program");
        std::process::exit(0);
    }

    println!("{}", HELP);

    loop {
        match client.tick_start() {
            ClientTickResult::ReceivedMessage(tick_result) => {
                use_tick_result(&client, tick_result);
                match inside_tick(&client, &mut line_receiver) {
                    Some(disconnection) => {
                        let state = client.disconnect(disconnection).await.unwrap();
                        println!("Client disconnected itself: {:?}", state);
                        std::process::exit(0);
                    }
                    None => {}
                };

                client.tick_after_message();
            }
            ClientTickResult::Disconnected => {
                println!(
                    "Client disconnected, reason: {:?}",
                    client.take_disconnect_reason().unwrap()
                );
                std::process::exit(0);
            }
            _ => (),
        }

        // The client tick check rate should be at least slightly faster than the server tick rate.
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn use_tick_result(_client: &Client, tick_result: ReceivedMessageClientTickResult) {
    let message = tick_result.message.to_packet_list();
    for deserialized_packet in message {
        if let Ok(message_packet) = deserialized_packet.packet.downcast::<ChatLinePacket>() {
            println!("● {}", message_packet.line);
        }
    }
}

fn inside_tick(
    client: &Client,
    line_receiver: &mut mpsc::UnboundedReceiver<String>,
) -> Option<Option<GracefullyDisconnection>> {
    while let Ok(line) = line_receiver.try_recv() {
        if line.starts_with("msg") {
            if line == "msg" {
                println!("No message provided, use `help` to see the commands and their usage");
            } else {
                let message = &line[4..];
                client.send_packet(&MessagePacket {
                    message: message.to_owned(),
                });
            }
        } else if line.starts_with("exit") {
            if line == "exit" {
                println!("Leaving program without sending a message");
                return Some(None);
            } else {
                let message = &line[5..];
                println!("Leaving program sending: {:?} message", message);
                let disconnection = GracefullyDisconnection {
                    timeout: Duration::from_secs(3),
                    message: SerializedPacketList::single(client.packet_registry().serialize(
                        &LeavePacket {
                            message: message.to_owned(),
                        },
                    )),
                };

                return Some(Some(disconnection));
            }
        } else if line.starts_with("help") {
            println!("{}", HELP);
        } else {
            println!(
                "Command not found ({}), use `help` to see the commands and their usage",
                line
            );
        }
    }
    None
}

async fn console_reader(line_sender: mpsc::UnboundedSender<String>) {
    let stdin = io::stdin();
    let reader = io::BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await.expect("Failed to read next line") {
        line_sender.send(line).unwrap();
    }
}

const HELP: &str = "
    - msg <message>
        Send a public message in the chat
    - exit <message>
        Leaves the chat sending a message
    - exit
        Leaves the chat without sending a message
    - help
        Show the commands usage
";
