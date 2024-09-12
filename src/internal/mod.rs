use std::{sync::Arc, time::Instant};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Nonce};

use messages::MessagePart;

use crate::LimitedMessage;

pub mod auth;
pub mod messages;
pub mod rt;
pub mod utils;

pub type MessageChannelType = u8;
pub struct MessageChannel;

pub const MESSAGE_CHANNEL_SIZE: usize = 1;

impl MessageChannel {
    pub const MESSAGE_PART_CONFIRM: MessageChannelType = 0;
    pub const MESSAGE_PART_SEND: MessageChannelType = 1;
    pub const REJECTION_CONFIRM: MessageChannelType = 2;
    pub const AUTH_MESSAGE: MessageChannelType = 3;
    pub const PUBLIC_KEY_SEND: MessageChannelType = 4;
    pub const REJECTION_JUSTIFICATION: MessageChannelType = 5;
}

pub struct SentMessagePart {
    /// The last instant that the bytes were sent.
    pub last_sent_time: Instant,
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

/// Justified rejection message.
pub struct JustifiedRejectionContext {
    /// The instant that the disconnection was made.
    pub rejection_instant: Instant,
    /// The serialized message to send, confirming the disconnect.
    pub finished_bytes: Vec<u8>,
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
