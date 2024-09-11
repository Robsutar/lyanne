use std::{collections::VecDeque, time::Duration};

/// A struct to monitor and calculate the average duration of a fixed-size buffer of recent durations.
pub struct DurationMonitor {
    stored: VecDeque<Duration>,
    total: Duration,
}

impl DurationMonitor {
    /// Initializes the DurationMonitor with a fixed-size buffer filled with the given initial duration.
    ///
    /// # Arguments
    ///
    /// * `duration` - The initial duration to fill the buffer with.
    /// * `size` - The size of the buffer.
    ///
    /// # Errors
    ///
    /// If the size exceeds the maximum allowable size (`u32::MAX`).
    pub fn try_filled_with(duration: Duration, size: usize) -> Result<Self, ()> {
        if size > u32::MAX as usize {
            Err(())
        } else {
            let mut stored = VecDeque::new();
            stored.resize(size, duration);
            Ok(Self {
                stored,
                total: duration * size as u32,
            })
        }
    }

    /// Adds a new duration to the buffer, updates the total and the average duration.
    ///
    /// # Arguments
    ///
    /// * `duration` - The new duration to add to the buffer.
    pub fn push(&mut self, duration: Duration) {
        let removed = self.stored.pop_front().unwrap();
        self.total -= removed;
        self.stored.push_back(duration);
        self.total += duration;
    }

    /// Returns the current average duration of the buffer.
    ///
    /// # Returns
    ///
    /// * `Duration` - The average duration of the durations in the buffer.
    pub fn average_value(&self) -> Duration {
        self.total / self.stored.len() as u32
    }
}

/// Represents properties for RTT (Round-Trip Time) calculation
pub struct RttProperties {
    alpha: f64, // Weight given to new RTT measurements
    beta: f64,  // Weight given to new variations in RTT measurements
}

impl RttProperties {
    /// Constructs a new `RttProperties` instance with the given `alpha` and `beta` values.
    ///
    /// # Arguments
    ///
    /// * `alpha` - Weight for new RTT measurements
    /// * `beta` - Weight for new variations in RTT measurements
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self { alpha, beta }
    }
}

/// Represents a calculator for RTT (Round-Trip Time)
pub struct RttCalculator {
    /// Estimated round-trip time
    estimated: Duration,
    /// Variation in round-trip time
    var: Duration,
}

impl RttCalculator {
    /// Constructs a new `RttCalculator` instance with an initial RTT value.
    ///
    /// # Arguments
    ///
    /// * `initial_rtt` - The initial round-trip time value
    ///
    /// The initial variation is set to half of the initial RTT.
    pub fn new(initial_rtt: Duration) -> Self {
        RttCalculator {
            estimated: initial_rtt,
            var: initial_rtt / 2,
        }
    }

    /// Updates the estimated RTT and variation based on new RTT measurements.
    ///
    /// # Arguments
    ///
    /// * `properties` - The `RttProperties` containing alpha and beta values
    /// * `new_rtt` - The new round-trip time measurement
    ///
    /// Returns the updated RTT with a safety margin (estimated + 4 * variation).
    pub fn update_rtt(&mut self, properties: &RttProperties, new_rtt: Duration) -> Duration {
        let new_rtt_secs = new_rtt.as_secs_f64();
        let estimated_secs = self.estimated.as_secs_f64();
        let var_secs = self.var.as_secs_f64();

        let new_var = (1.0 - properties.beta) * var_secs
            + properties.beta * (new_rtt_secs - estimated_secs).abs();
        let new_estimated =
            (1.0 - properties.alpha) * estimated_secs + properties.alpha * new_rtt_secs;

        self.var = Duration::from_secs_f64(new_var);
        self.estimated = Duration::from_secs_f64(new_estimated);

        self.estimated + self.var * 4
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_push_replaces_oldest_duration() {
        let initial_duration = Duration::from_secs(1);
        let mut monitor = DurationMonitor::try_filled_with(initial_duration, 3).unwrap();

        monitor.push(Duration::from_secs(2));
        assert_eq!(
            monitor.average_value(),
            Duration::from_millis(1000) + Duration::from_millis(1000) / 3
        ); // (1 + 1 + 2) / 3 ~= 1333,333 ms

        monitor.push(Duration::from_secs(3));
        assert_eq!(monitor.average_value(), Duration::from_millis(2000)); // (1 + 2 + 3) / 3 = 2000 ms

        monitor.push(Duration::from_secs(4));
        assert_eq!(monitor.average_value(), Duration::from_millis(3000)); // (2 + 3 + 4) / 3 = 3000 ms
    }
}
