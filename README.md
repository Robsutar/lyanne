[![Crate](https://img.shields.io/crates/v/lyanne.svg)](https://crates.io/crates/lyanne)
[![Docs](https://docs.rs/lyanne/badge.svg)](https://docs.rs/lyanne/latest/lyanne/)
[![License](https://img.shields.io/badge/license-MIT%2FApache-blue.svg)](LICENSE-MIT)

# Crate in development, not stable/secure for production usage!

# lyanne

Efficient, tick-oriented communication framework for server-client architectures.

- ✅ **Flexible Runtimes**: Choose between `rt_async_executor`, `rt_async_std`, `rt_bevy`, `rt_smol` or `rt_tokio` runtime environments for seamless integration with your ecosystem.
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
lyanne = { version = "0.4", features = [
    "rt_smol", # We need one runtime.
    "sd_bincode", # Serde + Bincode will help our packet serialization/deserialization.
    "server", # Server exclusive feature.
] }

# Our runtime.
smol = "^2.0.0"

# Our serializer.
serde = { version = "^1.0.0", features = ["derive"] }
bincode = "^1.0.0"
```

Adding lyanne dependency in client:

```toml
[dependencies]
lyanne = { version = "0.4", features = [
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

Sending packet to clients:

```rust,no_run
use lyanne::{server::*};
// Use your shared crate with the packets.
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

Sending packet to server:

```rust,no_run
use lyanne::{client::*};
// Use your shared crate with the packets.
use crate::packets::MessagePacket;

fn inside_tick(client: &Client) {
    let packet = MessagePacket {
        message: "Bar?".to_owned(),
    };

    client.send_packet(&packet);
}
```

See more complete examples in [examples](https://github.com/Robsutar/lyanne/tree/main/examples) folder, and in [crate documentation](https://docs.rs/lyanne/latest/lyanne/).