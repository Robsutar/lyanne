use std::{
    io::Read,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use bevy::core::NonSendMarker;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};

use crate::{
    messages::{MessagePart, MessagePartId},
    packets::SerializedPacketList,
    utils::RttProperties,
};

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "troubles_simulator")]
pub mod troubles_simulator;

pub struct MessagingProperties {
    pub part_limit: usize,
    pub timeout_interpretation: Duration,
    pub disconnect_reason_resend_delay: Duration,
    pub disconnect_reason_resend_cancel: Duration,
    pub initial_next_message_part_id: u8,
    pub initial_latency: Duration,
    pub packet_loss_rtt_properties: RttProperties,
    pub max_client_tick_bytes_len: usize,
}

impl Default for MessagingProperties {
    fn default() -> Self {
        Self {
            // 1024 buffer size, 1 for channel, 12 for nonce, 16 for encryption
            part_limit: 1024 - 1 - 12 - 16,
            timeout_interpretation: Duration::from_secs(10),
            disconnect_reason_resend_delay: Duration::from_secs(3),
            disconnect_reason_resend_cancel: Duration::from_secs(10),
            initial_next_message_part_id: 1,
            initial_latency: Duration::from_millis(50),
            packet_loss_rtt_properties: RttProperties::new(0.125, 0.25),
            max_client_tick_bytes_len: 50000,
        }
    }
}

pub(crate) type MessageChannelType = u8;
pub(crate) struct MessageChannel;

impl MessageChannel {
    pub const MESSAGE_PART_CONFIRM: MessageChannelType = 0;
    pub const MESSAGE_PART_SEND: MessageChannelType = 1;
    pub const REJECTION_CONFIRM: MessageChannelType = 2;
    //TODO: AUTH_MESSAGE has no cryptography, probably some dtls implementation is needed here
    pub const AUTH_MESSAGE: MessageChannelType = 3;
    pub const PUBLIC_KEY_SEND: MessageChannelType = 4;
    pub const DISCONNECT_REQUEST: MessageChannelType = 5;
    pub const REJECTION_JUSTIFICATION: MessageChannelType = 6;
    pub const IGNORED_REASON: MessageChannelType = 7;
}

pub(crate) struct SentMessagePart {
    /// The instant that the part was sent by the first time.
    sent_instant: Instant,
    /// The last instant that the bytes were sent.
    last_sent_time: Instant,
    /// The serialized message part with all additional bytes (nonce, cryptograph, channel).
    pub finished_bytes: Arc<Vec<u8>>,
}

impl SentMessagePart {
    pub fn new(
        sent_instant: Instant,
        part: &MessagePart,
        cipher: &ChaCha20Poly1305,
        nonce: Nonce,
    ) -> Self {
        let cipher_bytes = cipher.encrypt(&nonce, part.as_bytes()).unwrap();
        println!(
            "before bytes: {:?}, after bytes {:?}",
            part.as_bytes().len(),
            cipher_bytes.len()
        );
        let mut exit = Vec::with_capacity(1 + nonce.len() + cipher_bytes.len());
        exit.push(MessageChannel::MESSAGE_PART_SEND);
        exit.extend_from_slice(&nonce);
        exit.extend(cipher_bytes);
        Self {
            sent_instant,
            last_sent_time: sent_instant,
            finished_bytes: Arc::new(exit),
        }
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

/// The context that caused an addr to be disconnected from the server.
pub struct JustifiedRejectionContext {
    /// The instant that the disconnection was made.
    rejection_instant: Instant,
    /// The last instant that the bytes were sent.
    last_sent_time: Option<Instant>,
    /// The serialized message to send to the addr, confirming the disconnect.
    ///
    /// That message has limited size.
    finished_bytes: Vec<u8>,
}

impl JustifiedRejectionContext {
    /// The message will be sent to the client when it tries to connect.
    pub fn from_serialized_list(rejection_instant: Instant, list: SerializedPacketList) -> Self {
        if list.bytes.len() > 1024 - 1 {
            panic!("Max bytes length reached.");
        }
        let mut finished_bytes = Vec::with_capacity(1 + list.bytes.len());
        finished_bytes.push(MessageChannel::REJECTION_JUSTIFICATION);
        finished_bytes.extend(list.bytes);
        Self {
            rejection_instant,
            last_sent_time: None,
            finished_bytes,
        }
    }
}
