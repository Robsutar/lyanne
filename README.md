# lyanne

Efficient, tick-oriented communication framework for server-client architectures.

- ✅ **Flexible Runtimes**: Choose between `rt_tokio` or `rt_bevy` runtime environments for seamless integration with your ecosystem.
- ✅ **Custom Serialization**: Use the `sd_bincode` feature for efficient packet serialization and deserialization.
- ✅ **Robust Security**: Secure your communication with the `auth_tls` feature using rustls for TLS encryption, or opt for `auth_tcp` with a reverse proxy like NGINX for encrypted TCP communication.
- ✅ **Tick-Based Synchronization**: Optimized for ping-pong (tick) oriented communication, ensuring precise timing and synchronization.
- ✅ **Guaranteed Message Ordering**: Maintain strict message order with built-in sequencing mechanisms.
- ✅ **Zero Packet Loss**: Ensure reliable data transmission with lossless packet delivery.
- ✅ **Low Latency**: Achieve minimal message latency using UDP communication.
- ✅ **IP Agnostic**: Support for scenarios where IP addresses can be ignored.
- ✅ **Granular Authentication**: Customize client authentication with options to accept or refuse connections based on specific criteria.
- ✅ **Throttled Communication**: Limit and control the flow of communication to meet your application's needs.
- ✅ **Async Performance**: Handle intensive tasks efficiently with asynchronous processing.
- ✅ **Synchronous Control**: Manage operations, like packet sending and tick handling, without the need to use async.
