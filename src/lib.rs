#![cfg_attr(docsrs, feature(doc_cfg))]

//! Efficient, tick-oriented communication framework for server-client architectures.
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
//! - Different ways of serializing/deserializing packages.
//! - Different authenticators, including the required/optional use of tls with rustls.
//!
//! All within features, keeping compilation time fast.
//!
//! # Examples
//! Adding lyanne dependency in server:
//!
//! ```toml
//! [dependencies]
//! lyanne = { version = "0.4", features = [
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
//! lyanne = { version = "0.4", features = [
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
//!

#[cfg(feature = "bevy_packet_schedules")]
pub use bevy_ecs;

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Nonce};
use messages::{ENCRYPTION_SPACE, NONCE_SIZE};

use crate::{
    messages::{MessagePart, MessagePartId},
    packets::SerializedPacketList,
    utils::RttProperties,
};

pub(crate) mod internal;
pub mod messages;
pub mod packets;
pub(crate) mod rt;
pub(crate) mod sd;
pub(crate) mod utils;

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

pub(crate) mod auth;

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
            // 1024 buffer size
            part_limit: 1024 - MESSAGE_CHANNEL_SIZE - NONCE_SIZE - ENCRYPTION_SPACE,
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

pub(crate) type MessageChannelType = u8;
pub(crate) struct MessageChannel;

pub(crate) const MESSAGE_CHANNEL_SIZE: usize = 1;

#[allow(dead_code)]
impl MessageChannel {
    pub const MESSAGE_PART_CONFIRM: MessageChannelType = 0;
    pub const MESSAGE_PART_SEND: MessageChannelType = 1;
    pub const REJECTION_CONFIRM: MessageChannelType = 2;
    pub const AUTH_MESSAGE: MessageChannelType = 3;
    pub const PUBLIC_KEY_SEND: MessageChannelType = 4;
    pub const REJECTION_JUSTIFICATION: MessageChannelType = 5;
    pub const IGNORED_REASON: MessageChannelType = 6;
}

#[allow(dead_code)]
pub(crate) struct SentMessagePart {
    /// The last instant that the bytes were sent.
    last_sent_time: Instant,
    /// The serialized message part with all additional bytes (nonce, cryptograph, channel).
    pub finished_bytes: Arc<Vec<u8>>,
}

impl SentMessagePart {
    pub fn no_cryptography(sent_instant: Instant, part: MessagePart) -> Self {
        let part_bytes = part.to_bytes();
        let mut exit = Vec::with_capacity(MESSAGE_CHANNEL_SIZE + part_bytes.len());
        exit.push(MessageChannel::MESSAGE_PART_SEND);
        exit.extend(part_bytes);
        Self {
            last_sent_time: sent_instant,
            finished_bytes: Arc::new(exit),
        }
    }
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    pub fn encrypted(sent_instant: Instant, part: MessagePart, cipher: &ChaCha20Poly1305) -> Self {
        let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
        let cipher_bytes =
            SentMessagePart::cryptograph_message_part(part.as_bytes(), cipher, &nonce);
        let mut exit = Vec::with_capacity(MESSAGE_CHANNEL_SIZE + nonce.len() + cipher_bytes.len());
        exit.push(MessageChannel::MESSAGE_PART_SEND);
        exit.extend_from_slice(&nonce);
        exit.extend(cipher_bytes);
        Self {
            last_sent_time: sent_instant,
            finished_bytes: Arc::new(exit),
        }
    }

    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    pub fn cryptograph_message_part(
        message_bytes: &[u8],
        cipher: &ChaCha20Poly1305,
        nonce: &Nonce,
    ) -> Vec<u8> {
        cipher.encrypt(&nonce, message_bytes).unwrap()
    }
}

/// Properties for the client bytes read handlers, used in `create_read_handler`.
pub struct ReadHandlerProperties {
    /// Number of asynchronous tasks that must be slacking when receiving packets.
    pub target_surplus_size: u16,
    /// Max time to try read `pre_read_next_bytes`.
    pub timeout: Duration,
    /// Actual number of active asynchronous read handlers.
    pub active_count: Arc<RwLock<u16>>,
}

impl Default for ReadHandlerProperties {
    fn default() -> ReadHandlerProperties {
        ReadHandlerProperties {
            target_surplus_size: 5u16,
            timeout: Duration::from_secs(15),
            active_count: Arc::new(RwLock::new(0u16)),
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
        if list.bytes.len() > 1024 - MESSAGE_CHANNEL_SIZE - NONCE_SIZE - ENCRYPTION_SPACE {
            Err(())
        } else {
            Ok(LimitedMessage { list })
        }
    }

    /// # Panics
    /// If the list reached the max allowed size.
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

/// Justified rejection message.
pub(crate) struct JustifiedRejectionContext {
    /// The instant that the disconnection was made.
    rejection_instant: Instant,
    /// The serialized message to send, confirming the disconnect.
    finished_bytes: Vec<u8>,
}

impl JustifiedRejectionContext {
    pub fn no_cryptography(rejection_instant: Instant, message: LimitedMessage) -> Self {
        let list_bytes = message.to_list().bytes;
        let mut exit = Vec::with_capacity(MESSAGE_CHANNEL_SIZE + list_bytes.len());
        exit.push(MessageChannel::REJECTION_JUSTIFICATION);
        exit.extend(list_bytes);
        Self {
            rejection_instant,
            finished_bytes: exit,
        }
    }
    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    pub fn encrypted(
        rejection_instant: Instant,
        message: LimitedMessage,
        cipher: &ChaCha20Poly1305,
    ) -> Self {
        let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
        let cipher_bytes =
            SentMessagePart::cryptograph_message_part(&message.to_list().bytes, cipher, &nonce);
        let mut exit = Vec::with_capacity(MESSAGE_CHANNEL_SIZE + nonce.len() + cipher_bytes.len());
        exit.push(MessageChannel::REJECTION_JUSTIFICATION);
        exit.extend_from_slice(&nonce);
        exit.extend(cipher_bytes);
        Self {
            rejection_instant,
            finished_bytes: exit,
        }
    }

    #[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
    pub fn cryptograph_message_part(
        message_bytes: &[u8],
        cipher: &ChaCha20Poly1305,
        nonce: &Nonce,
    ) -> Vec<u8> {
        cipher.encrypt(&nonce, message_bytes).unwrap()
    }
}
