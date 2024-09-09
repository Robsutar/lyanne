use std::io;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
use crate::{
    messages::{MINIMAL_PART_BYTES_SIZE, NONCE_SIZE},
    MESSAGE_CHANNEL_SIZE,
};

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub(super) struct InnerAuthTcpBased {
    /// The cipher used for encrypting and decrypting messages.
    pub cipher: ChaCha20Poly1305,
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
impl InnerAuthTcpBased {
    pub(crate) fn extract(&self, bytes: &Vec<u8>) -> io::Result<Vec<u8>> {
        if bytes.len() < MESSAGE_CHANNEL_SIZE + MINIMAL_PART_BYTES_SIZE + NONCE_SIZE {
            Err(InnerAuth::insufficient_minimal_bytes_error())
        } else {
            let nonce = Nonce::from_slice(
                &bytes[MESSAGE_CHANNEL_SIZE..(MESSAGE_CHANNEL_SIZE + NONCE_SIZE)],
            );
            let cipher_text = &bytes[(MESSAGE_CHANNEL_SIZE + NONCE_SIZE)..];

            match self.cipher.decrypt(nonce, cipher_text) {
                Ok(message_part_bytes) => Ok(message_part_bytes),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Message decrypt failed {}", e),
                )),
            }
        }
    }
}

pub(super) enum InnerAuth {
    NoCryptography,
    #[cfg(feature = "auth_tcp")]
    RequireTcp(InnerAuthTcpBased),
    #[cfg(feature = "auth_tls")]
    RequireTls(InnerAuthTcpBased),
}

impl InnerAuth {
    pub fn insufficient_minimal_bytes_error() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "Insufficient minimal bytes.")
    }

    pub fn sent_part_of(&self, sent_instant: Instant, part: MessagePart) -> SentMessagePart {
        match self {
            InnerAuth::NoCryptography => SentMessagePart::no_cryptography(sent_instant, part),
            #[cfg(feature = "auth_tcp")]
            InnerAuth::RequireTcp(props) => {
                SentMessagePart::encrypted(sent_instant, part, &props.cipher)
            }
            #[cfg(feature = "auth_tls")]
            InnerAuth::RequireTls(props) => {
                SentMessagePart::encrypted(sent_instant, part, &props.cipher)
            }
        }
    }
}
