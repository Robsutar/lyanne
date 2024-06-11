use rand::Rng;
use std::{ops::Range, time::Duration};

/// Struct representing the properties of a network problem simulator.
/// In local tests, we rarely encountered common communication issues between different networks,
/// such as ping (response delay between client and server) and packet loss.
///
/// This struct is designed to simulate these scenarios, even when exchanging information locally.
pub struct NetTroublesSimulatorProperties {
    /// The range of ping (response delay between client and server) variations.
    pub simulated_ping: Option<Range<Duration>>,
    /// The range of packet loss variations.
    /// (0.0 = 0% chance of packet loss, 1.0 = 100% chance of packet loss)
    ///
    /// Packet loss refers to the complete loss of a data packet sent over the socket.
    /// While the server can handle packet losses, they cause delays in data transfer.
    ///
    /// Packet loss can occur due to various factors, including network fluctuations and hardware issues.
    ///
    /// See [`great_condition`], [`good_condition`], [`bad_condition`], and [`horrible_condition`]
    /// for examples of how these percentages vary in real environments.
    pub simulated_packet_loss: Option<Range<f64>>,
}

impl NetTroublesSimulatorProperties {
    /// Returns a configuration simulating great network conditions.
    pub fn great_condition() -> Self {
        Self {
            simulated_ping: Some(Duration::from_millis(10)..Duration::from_millis(30)),
            simulated_packet_loss: Some(0.0..0.01),
        }
    }

    /// Returns a configuration simulating good network conditions.
    pub fn good_condition() -> Self {
        Self {
            simulated_ping: Some(Duration::from_millis(20)..Duration::from_millis(60)),
            simulated_packet_loss: Some(0.01..0.02),
        }
    }

    /// Returns a configuration simulating bad network conditions.
    pub fn bad_condition() -> Self {
        Self {
            simulated_ping: Some(Duration::from_millis(50)..Duration::from_millis(120)),
            simulated_packet_loss: Some(0.02..0.05),
        }
    }

    /// Returns a configuration simulating horrible network conditions.
    pub fn horrible_condition() -> Self {
        Self {
            simulated_ping: Some(Duration::from_millis(120)..Duration::from_millis(340)),
            simulated_packet_loss: Some(0.05..0.10),
        }
    }

    /// Generates a random ping delay within the specified range.
    ///
    /// # Returns
    /// - `None` if there is no range set in [`simulated_ping`].
    /// - A `Duration` value within the range set in [`simulated_ping`].
    pub fn ranged_ping_delay(&self) -> Option<Duration> {
        if let Some(range) = &self.simulated_ping {
            let mut rng = rand::thread_rng();
            let start = range.start.as_millis();
            let end = range.end.as_millis();
            let random_millis = rng.gen_range(start..end);
            Some(Duration::from_millis(random_millis as u64))
        } else {
            None
        }
    }

    /// Simulates a random packet loss based on the specified range.
    ///
    /// # Returns
    /// - `true` if a packet loss event occurs.
    /// - `false` if no packet loss range is set or no packet loss event occurs.
    pub fn ranged_packet_loss(&self) -> bool {
        if let Some(range) = &self.simulated_packet_loss {
            let mut rng = rand::thread_rng();
            let start = range.start;
            let end = range.end;
            let random_percent = rng.gen_range(start..end);
            rng.gen_bool(random_percent)
        } else {
            false
        }
    }
}
