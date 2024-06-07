use std::time::Duration;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub struct MessagingProperties {
    pub part_limit: usize,
    pub timeout_interpretation: Duration,
    pub packet_loss_interpretation: Duration,
    pub initial_next_message_part_id: u8,
}

impl Default for MessagingProperties {
    fn default() -> Self {
        Self {
            part_limit: 1024,
            timeout_interpretation: Duration::from_secs(10),
            packet_loss_interpretation: Duration::from_millis(100),
            initial_next_message_part_id: 1,
        }
    }
}

pub type MessageChannelType = u8;
pub struct MessageChannel;

impl MessageChannel {
    pub const MESSAGE_PART_CONFIRM: MessageChannelType = 0;
    pub const MESSAGE_PART_SEND: MessageChannelType = 1;
}
