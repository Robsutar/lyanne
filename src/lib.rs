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
//! lyanne = { version = "0.3", features = [
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
//! lyanne = { version = "0.3", features = [
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

#[cfg(feature = "bevy_packet_schedules")]
pub use bevy_ecs;

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Nonce};
use messages::NONCE_SIZE;

use crate::{
    messages::{MessagePart, MessagePartId},
    packets::SerializedPacketList,
    utils::RttProperties,
};

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
            // 1024 buffer size, 16 for encryption
            part_limit: 1024 - MESSAGE_CHANNEL_SIZE - NONCE_SIZE - 16,
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

/// Justified rejection message.
#[allow(dead_code)]
pub struct JustifiedRejectionContext {
    /// The instant that the disconnection was made.
    rejection_instant: Instant,
    /// The last instant that the bytes were sent.
    last_sent_time: Option<Instant>,
    /// The serialized message to send, confirming the disconnect.
    finished_bytes: Vec<u8>,
}

impl JustifiedRejectionContext {
    pub fn try_from_serialized_list(
        rejection_instant: Instant,
        list: SerializedPacketList,
    ) -> Result<Self, ()> {
        if list.bytes.len() > 1024 - MESSAGE_CHANNEL_SIZE - NONCE_SIZE {
            Err(())
        } else {
            let mut finished_bytes = Vec::with_capacity(1 + list.bytes.len());
            finished_bytes.push(MessageChannel::REJECTION_JUSTIFICATION);
            finished_bytes.extend(list.bytes);
            Ok(Self {
                rejection_instant,
                last_sent_time: None,
                finished_bytes,
            })
        }
    }

    /// Loads from [`SerializedPacketList`].
    ///
    /// # Panics
    /// If the message reached the maximum byte length.
    pub fn from_serialized_list(rejection_instant: Instant, list: SerializedPacketList) -> Self {
        JustifiedRejectionContext::try_from_serialized_list(rejection_instant, list)
            .expect("Message reached the maximum byte length.")
    }
}
