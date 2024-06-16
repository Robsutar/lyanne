use std::time::Duration;

use crate::utils::RttProperties;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "troubles_simulator")]
pub mod troubles_simulator;

pub struct MessagingProperties {
    pub part_limit: usize,
    pub timeout_interpretation: Duration,
    pub initial_next_message_part_id: u8,
    pub initial_latency: Duration,
    pub packet_loss_rtt_properties: RttProperties,
}

impl Default for MessagingProperties {
    fn default() -> Self {
        Self {
            part_limit: 896,
            timeout_interpretation: Duration::from_secs(10),
            packet_loss_interpretation: Duration::from_millis(100),
            initial_next_message_part_id: 1,
            initial_latency: Duration::from_millis(50),
            packet_loss_rtt_properties: RttProperties::new(0.125, 0.25),
        }
    }
}

pub type MessageChannelType = u8;
pub struct MessageChannel;

impl MessageChannel {
    pub const MESSAGE_PART_CONFIRM: MessageChannelType = 0;
    pub const MESSAGE_PART_SEND: MessageChannelType = 1;
    pub const AUTHENTICATION: MessageChannelType = 2;
}
