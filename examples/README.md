# Examples

This folder contains a variety of examples, using all the features and runtimes available in the crate.

## Simple examples
The simple examples end with the suffix "-simple", and they are all compatible with each other, so you can use `tokio-simple-server` to communicate with `smol-simple-client` and any other `simple-client`. Examples and their used features:
- **async-executor-simple**: rt_async_executor, sd_bincode, client, server.
- **async-std-simple**: rt_async_std, sd_bincode, client, server.
- **bevy-simple**: rt_bevy, sd_bincode, client, server.
- **smol-simple**: rt_smol, sd_bincode, client, server.
- **tokio-simple**: rt_tokio, sd_bincode, client, server.

## async-std-tcp
It uses TCP for key transfer to encrypt the communication.
It is based on `async-std-simple`, so it is easy to compare what the `auth_tcp` feature changes.

**WARNING** this feature alone is not responsible for successfully encrypting the entire connection, you also need a certificate on top of this TCP port, like a reverse proxy.

**Used features**: rt_async_std, auth_tcp, sd_bincode, client, server.

## async-std-tls
It uses TLS with rustls for key transfer to encrypt the communication.
It is based on `async-std-simple`, so it is easy to compare what the `auth_tls` feature changes.

**WARNING** The encryption of the crate with rustls has not yet been subjected to a series of tests.

**Used features**: rt_async_std, auth_tls, sd_bincode, client, server.

## bevy-pong
Example that uses a server and two clients to create a match of the game [Pong](https://pt.wikipedia.org/wiki/Pong). Uses `bevy_packet_schedules` feature to automatically create ScheduledLabels for the packets and has optional tls/tcp authenticator.

**Used features**: rt_bevy, bevy_packet_schedules, store_unexpected, auth_tls, auth_tcp, sd_bincode, client, server.

## tokio-chat
Example that makes a simple public chat. Uses `deserialized_message_map` to store packages in maps, instead of storing them in lists, making it quick and easy to search for packages of the same type.

**Used features**: rt_tokio, deserialized_message_map, store_unexpected, sd_bincode, client, server.