# lyanne

Efficient, tick-oriented communication framework for server-client architectures.

- ✅ **Flexible Runtimes**: Choose between `rt_tokio` or `rt_bevy` runtime environments for seamless integration with your ecosystem.
- ✅ **Custom Serialization**: Use the `sd_bincode` feature for efficient packet serialization and deserialization.
- ❗ **Cryptography**: Secure your communication with the `auth_tls` feature using rustls for TLS encryption, or opt for `auth_tcp` with a reverse proxy like NGINX for encrypted TCP communication. **WARNING**: Further testing is required to validate the security of authenticators.
- ✅ **Tick-Based Synchronization**: Optimized for round-trip (tick) oriented communication, ensuring precise timing and synchronization.
- ✅ **Guaranteed Message Ordering**: Maintain strict message order with built-in sequencing mechanisms.
- ✅ **Zero Packet Loss**: Ensure reliable data transmission with lossless packet delivery.
- ✅ **Low Latency**: Achieve minimal message latency using UDP communication.
- ✅ **IP Agnostic**: Support for scenarios where IP addresses can be ignored.
- ✅ **Granular Authentication**: Tailor client authentication with fine-grained control over connection acceptance based on specific criteria.
- ✅ **Throttled Communication**: Limit and control the flow of communication to meet your application's needs.
- ✅ **Async Performance**: Handle intensive tasks efficiently with asynchronous processing.
- ✅ **Synchronous Control**: Manage operations, such as packet sending and tick handling, without relying on asynchronous code.
- ❌ **No Automatic ECS Replication**: Entity Component System (ECS) replication is not automated.
- ❌ **No WASM Support**: WebAssembly (WASM) not yet available.

## Examples

Adding lyanne dependency in server:

```toml
[dependencies]
lyanne = { version = "0.2.0", features = [
    "rt_bevy", # We need one runtime.
    "sd_bincode", # Serde + Bincode will help our packet serialization/deserialization.
    "server", # Server exclusive feature.
] }

# Our runtime.
bevy = "^0.14.0"

# Our serializer.
serde = { version = "^1.0.0", features = ["derive"] }
bincode = "^1.0.0"
```

Adding lyanne dependency in client:

```toml
[dependencies]
lyanne = { version = "0.2.0", features = [
    # ...
    "client", # Same as the server, but using "client" instead of "server".
] }
```

Creating packets with `sd_bincode`:

```rust,no_run
use lyanne::packets::Packet;
use serde::{Deserialize, Serialize};

#[derive(Packet, Deserialize, Serialize, Debug)]
struct HelloPacket {
    player_name: String,
}

#[derive(Packet, Deserialize, Serialize, Debug)]
struct MessagePacket {
    message: String,
}
```

Binding a server:

```rust,no_run
use lyanne::{packets::*, server::*, *};
use std::{net::SocketAddr, sync::Arc};
use crate::packets::HelloPacket;

fn main() {
    let mut packet_registry = PacketRegistry::with_essential();
    packet_registry.add::<HelloPacket>();

    let addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let server_properties = Arc::new(ServerProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography;

    let bind_handle = Server::bind(
        addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        server_properties,
        authenticator_mode,
    );
}
```

Connecting a client:

```rust,no_run
use lyanne::{client::*, packets::*, *};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use crate::packets::HelloPacket;

fn main() {
    let mut packet_registry = PacketRegistry::with_essential();
    packet_registry.add::<HelloPacket>();

    let remote_addr: SocketAddr = "127.0.0.1:8822".parse().unwrap();
    let messaging_properties = Arc::new(MessagingProperties::default());
    let read_handler_properties = Arc::new(ReadHandlerProperties::default());
    let client_properties = Arc::new(ClientProperties::default());
    let authenticator_mode = AuthenticatorMode::NoCryptography(AuthenticationProperties {
        message: SerializedPacketList::create(vec![packet_registry.serialize(
            &HelloPacket {
                player_name: "Josh",
            },
        )]),
        timeout: Duration::from_secs(10),
    });

    let connect_handle = Client::connect(
        remote_addr,
        Arc::new(packet_registry),
        messaging_properties,
        read_handler_properties,
        client_properties,
        authenticator_mode,
    );
}
```

Sending packets:

```rust,no_run
use lyanne::{server::*};
use crate::packets::MessagePacket;

fn inside_tick(server: &Server) {
    let packet = MessagePacket {
        message: "Foo!".to_owned(),
    };

    for client in server.connected_clients_iter() {
        server.send_packet(&client, &packet);
    }
}
```

Authenticating clients:

```rust,no_run
use lyanne::{server::*};
use crate::packets::HelloPacket;

fn use_tick_result(server: &Server, tick_result: ServerTickResult) {
    for (addr, (addr_to_auth, message)) in tick_result.to_auth {
        if let Ok(hello_packet) = message
            .to_packet_list()
            .remove(0)
            .packet
            .downcast::<HelloPacket>()
        {
            if hello_packet.player_name == "Josh" {
                println!(
                    "authenticating client {:?}, packet: {:?}",
                    addr, hello_packet
                );

                server.authenticate(addr, addr_to_auth);
            }
        }
    }
}
```

Server tick management:

```rust,no_run
use lyanne::server::*;
use crate::{use_tick_result,inside_tick};

fn complete_tick(server: &Server) {
    let tick_result = server.tick_start();

    use_tick_result(server, tick_result);
    inside_tick();

    server.tick_end();
}
```

See more complete examples in `examples` folder.