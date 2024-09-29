#![cfg_attr(docsrs, feature(doc_cfg))]

//! Efficient, tick-oriented communication library for server-client architectures.
//!
//! Lyanne is an abstraction for communication between client and server, greatly
//! simplifying the process, maintaining low latency and low resource usage.
//!
//! Moves the most resource-intensive work to asynchronous operations, but both
//! client and server calls, such as sending/receiving packets, can be used in
//! synchronous contexts.
//!
//! Being highly customizable, Lyanne supports:
//! - Multiple runtimes.
//! - Different ways of serializing/deserializing packets.
//! - Different authenticators, including the required/optional use of tls with rustls.
//!
//! All within features, keeping compilation time fast.
//!
//! # Examples
//! Adding lyanne dependency in server:
//!
//! ```toml
//! [dependencies]
//! lyanne = { version = "0.5", features = [
//!     "rt_smol", # We need one runtime.
//!     "sd_bincode", # Serde + Bincode will help our packet serialization/deserialization.
//!     "server", # Server exclusive feature.
//! ] }
//!
//! # Our runtime.
//! smol = "^2.0.0"
//!
//! # Our serializer.
//! serde = { version = "^1.0.0", features = ["derive"] }
//! bincode = "^1.0.0"
//! ```
//!
//! Adding lyanne dependency in client:
//!
//! ```toml
//! [dependencies]
//! lyanne = { version = "0.5", features = [
//!     # ...
//!     "client", # Same as the server, but using "client" instead of "server".
//! ] }
//! ```
//!
//! Creating packets with `sd_bincode`:
//!
//! ```rust,no_run
//! use lyanne::packets::Packet;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct HelloPacket {
//!     player_name: String,
//! }
//!
//! #[derive(Packet, Deserialize, Serialize, Debug)]
//! struct MessagePacket {
//!     message: String,
//! }
//! ```
//!
//! # Cargo Features
//! No feature is enabled by default, but at least one runtime feature is required.
//!
//! Each feature is being used by at least one example inside [examples](https://github.com/Robsutar/lyanne/tree/main/examples),
//! see [README](https://github.com/Robsutar/lyanne/tree/main/examples#examples) for more information.
//!
//! |feature|description|
//! |-|-|
//! |client|Enable client exclusive module|
//! |server|Enable server exclusive module|
//! |rt_async_executor|Uses async-executor as runtime|
//! |rt_async_std|Uses async-std as runtime|
//! |rt_bevy|Uses bevy_tasks as runtime|
//! |rt_smol|Uses smol as runtime|
//! |rt_tokio|Uses tokio as runtime|
//! |sd_bincode|Uses serde + bincode as packet serializer/deserializer|
//! |auth_tcp|Uses Tcp socket to exchange keys to encrypt the udp communication. **Warning**: this feature alone is not responsible to encrypt the entire connection, some additional cryptography in that Tcp port is needed,such as a reverse proxy, like nginx.|
//! |auth_tls|Uses Tcp socket with tls (using rustls) to exchange keys to encrypt the udp communication. **Warning**: The encryption of the crate with rustls has not yet been subjected to a series of tests.|
//! |bevy_packet_schedules|Creates Scheduled Labels for structs that derive from Packet.|
//! |deserialized_message_map|Received packets will be read in maps (with the keys being the packet IDs), instead of being stored in a list. This does not affect communication, only the way the data is stored for reading.|
//! |store_unexpected|Stores unexpected communication errors in each tick, such as incorrect communication. It is generally a debugging tool and adds a small overhead.|
//! |no_panics|Removes the public crate functions that cause panic, leaving only the versions of the same that use the try_ prefix and have the return being a Result. The panic of those functions are usually related to unusual scenarios, such as incorrect use of [`server::AuthEntry`], incorrect use of tick cycle, sending unregistered packets...|
//!

#[cfg(feature = "bevy_packet_schedules")]
pub use bevy_ecs;
#[cfg(all(feature = "bevy_packet_schedules", not(any(feature = "sd_bincode"))))]
compile_error!("feature \"bevy_packet_schedules\" needs one serializer");

use std::time::Duration;

use internal::{
    messages::{ENCRYPTION_SPACE, NONCE_SIZE, UDP_BUFFER_SIZE},
    SentMessagePart, MESSAGE_CHANNEL_SIZE,
};

pub use internal::messages::{DeserializedMessage, MessagePartId};

use crate::{internal::utils::RttProperties, packets::SerializedPacketList};

#[cfg(any(feature = "server", feature = "client"))]
pub(crate) mod internal;

#[cfg(not(any(feature = "server", feature = "client")))]
#[allow(dead_code)]
pub(crate) mod internal;

pub mod packets;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client;

#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub mod server;

#[cfg(feature = "auth_tcp")]
pub mod auth_tcp;

#[cfg(feature = "auth_tls")]
pub mod auth_tls;

/// General properties for the communication messaging.
///
/// Needs to be the same both in the client and server.
pub struct MessagingProperties {
    pub part_limit: usize,
    pub timeout_interpretation: Duration,
    pub disconnect_reason_resend_delay: Duration,
    pub disconnect_reason_resend_cancel: Duration,
    pub initial_next_message_part_id: MessagePartId,
    pub initial_latency: Duration,
    pub packet_loss_rtt_properties: RttProperties,
    pub max_tick_bytes_len: usize,
}

impl Default for MessagingProperties {
    fn default() -> Self {
        Self {
            part_limit: UDP_BUFFER_SIZE - MESSAGE_CHANNEL_SIZE - NONCE_SIZE - ENCRYPTION_SPACE,
            timeout_interpretation: Duration::from_secs(10),
            disconnect_reason_resend_delay: Duration::from_secs(3),
            disconnect_reason_resend_cancel: Duration::from_secs(10),
            initial_next_message_part_id: 1,
            initial_latency: Duration::from_millis(50),
            packet_loss_rtt_properties: RttProperties::new(0.125, 0.25),
            max_tick_bytes_len: usize::MAX,
        }
    }
}

/// Properties for reading data via UdpSocket.
pub struct ReadHandlerProperties {
    /// Number of asynchronous tasks to receiving packets.
    pub target_tasks_size: u16,
}

impl Default for ReadHandlerProperties {
    fn default() -> ReadHandlerProperties {
        ReadHandlerProperties {
            target_tasks_size: 16u16,
        }
    }
}

/// Message limited by maximum socket send/receive bytes.
pub struct LimitedMessage {
    /// Packet list with limited size checked.
    list: SerializedPacketList,
}

impl LimitedMessage {
    /// # Errors
    /// If the list reached the max allowed size.
    pub fn try_new(list: SerializedPacketList) -> Result<Self, ()> {
        if list.bytes.len() > UDP_BUFFER_SIZE - MESSAGE_CHANNEL_SIZE - NONCE_SIZE - ENCRYPTION_SPACE
        {
            Err(())
        } else {
            Ok(LimitedMessage { list })
        }
    }

    /// Panic version of [`LimitedMessage::try_new`].
    ///
    /// # Panics
    /// If the list reached the max allowed size.
    #[cfg(not(feature = "no_panics"))]
    pub fn new(list: SerializedPacketList) -> Self {
        LimitedMessage::try_new(list).expect("Message reached the maximum byte length.")
    }

    pub(crate) fn to_list(self) -> SerializedPacketList {
        self.list
    }

    #[cfg(feature = "server")]
    pub(crate) fn clone(message: &LimitedMessage) -> LimitedMessage {
        LimitedMessage {
            list: SerializedPacketList {
                bytes: message.list.bytes.clone(),
            },
        }
    }
}
