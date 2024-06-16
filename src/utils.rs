use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
    io,
    time::Duration,
};

use crate::messages::MessagePartLargeId;

pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE: usize = (std::mem::size_of::<u8>() * 255) / 2;
pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8: u8 = ORDERED_ROTATABLE_U8_VEC_MAX_SIZE as u8;
pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U16: u16 = ORDERED_ROTATABLE_U8_VEC_MAX_SIZE as u16;

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
    /// # Panics
    ///
    /// Panics if the size exceeds the maximum allowable size (`u32::MAX`).
    pub fn filled_with(duration: Duration, size: usize) -> Self {
        if size > u32::MAX as usize {
            panic!("size exceeded the maximum DurationMonitor size");
        } else {
            let mut stored = VecDeque::new();
            stored.resize(size, duration);
            Self {
                stored,
                total: duration * size as u32,
            }
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

/// A trait that requires implementing a method to return a `u8` index.
/// This is used by `OrderedRotatableU8Vec` to get the `u8` value for sorting purposes.
pub trait IndexableU8 {
    fn index(&self) -> u8;
}
/// `OrderedRotatableU8Vec` is a data structure that maintains a vector of elements that implement the `IndexableU8` trait.
/// The vector can be sorted while considering the rotational property of the `u8` type, meaning it treats `255` followed by `0` as a valid rotation sequence.
///
/// The main features include:
/// - Creating an empty or pre-allocated vector.
/// - Getting a mutable reference to the internal vector for modifications.
/// - Sorting the vector based on the rotational ordering of the `u8` keys.
///
/// Note: Modifications through the mutable reference require a subsequent call to `order()` to re-establish the intended order.
pub struct OrderedRotatableU8Vec<T: IndexableU8> {
    vec: Vec<T>,
}

impl<T: IndexableU8> OrderedRotatableU8Vec<T> {
    pub fn new() -> Self {
        OrderedRotatableU8Vec { vec: Vec::new() }
    }
    pub fn with_capacity(capacity: usize) -> Self {
        OrderedRotatableU8Vec {
            vec: Vec::with_capacity(capacity),
        }
    }
    pub fn take(vec: Vec<T>) -> Self {
        OrderedRotatableU8Vec { vec }
    }
    /// Modifications in the returned reference will not order the vec.
    /// Use [`order`] after modifying the vec through this reference.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ordered_vec = OrderedRotatableU8Vec::new();
    /// let vec_mut = ordered_vec.vec_mut();
    /// // modify vec_mut here
    /// ordered_vec.order();
    /// ```
    pub fn vec_mut(&mut self) -> &mut Vec<T> {
        &mut self.vec
    }

    /// Returns a reference of the vec
    pub fn vec_ref(&self) -> &Vec<T> {
        &self.vec
    }

    /// Returns the vec, with ownership
    pub fn take_vec(self) -> Vec<T> {
        self.vec
    }

    /// Sort the vec itself to consider rotations using [`wrapping_add(1)`] in the tuples' u8
    ///
    /// # Errors
    /// Returns an error if the vec size exceeds [`ORDERED_ROTATABLE_U8_VEC_MAX_SIZE`].
    ///
    /// See also [`compare_with_rotation`].
    pub fn order(&mut self) -> io::Result<()> {
        if self.vec.len() > ORDERED_ROTATABLE_U8_VEC_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Max size reached".to_owned(),
            ));
        }
        self.vec
            .sort_by(|a, b| compare_with_rotation(a.index(), b.index()));
        Ok(())
    }
}

/// This will sort, but considering that the list can rotate the value of u8,
/// that is, when a value is [`255u8`], the next value (using [`wrapping_add(1)`]) will be 0
///
/// Observation: This will not work if the list is larger than [`ORDERED_ROTATABLE_U8_VEC_MAX_SIZE`].
///
/// # Scenarios
///
/// - If `a = 250` and `b = 1`, the result should be `Less` because `a` comes before `b`.
/// - If `a = 250` and `b = 232`, the result should be `Greater` because `a` comes after `b`.
pub fn compare_with_rotation(a: u8, b: u8) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    if a > b {
        if a - b <= ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8 {
            // a came after b
            return Ordering::Greater;
        } else {
            // a came before b
            return Ordering::Less;
        }
    } else {
        // a < b
        if b - a <= ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8 {
            // a came before b
            return Ordering::Less;
        } else {
            // a came after b
            return Ordering::Greater;
        }
    }
}

pub fn remove_with_rotation<T>(tree: &mut BTreeMap<u16, T>, index: u8) -> Option<T> {
    if let Some((first, _)) = tree.first_key_value() {
        let large_index = index as MessagePartLargeId;
        if index <= ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8 {
            if *first <= ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U16 {
                return tree.remove(&large_index);
            } else {
                return tree.remove(&(large_index.wrapping_add(256)));
            }
        } else {
            return tree.remove(&large_index);
        }
    } else {
        return None;
    }
}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};

    use crate::messages::{MessagePartId, MessagePartLargeId};

    use super::*;

    struct SimpleIndexableU8 {
        index: u8,
    }

    impl IndexableU8 for SimpleIndexableU8 {
        fn index(&self) -> u8 {
            self.index
        }
    }

    #[test]
    fn test_push_replaces_oldest_duration() {
        let initial_duration = Duration::from_secs(1);
        let mut monitor = DurationMonitor::filled_with(initial_duration, 3);

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

    #[test]
    fn rotation_check() {
        let large: MessagePartLargeId = 255;
        let next: MessagePartId = ((large + 1) % 256) as MessagePartId;
        assert_eq!(0, next);
    }

    #[test]
    fn remove_with_rotation_check() {
        let initial_indexes: Vec<u8> = vec![0, 45, 99, 122, 126, 127, 144, 200, 240, 250, 254, 255];
        let epochs = 11;

        for initial_index in initial_indexes {
            let mut tree: BTreeMap<u16, usize> = BTreeMap::new();

            {
                let mut index = initial_index as u16;
                for epoch in 0..epochs + 1 {
                    tree.insert(index, epoch);
                    index += 1;
                }
            }

            assert_eq!(
                remove_with_rotation(&mut tree, initial_index.wrapping_sub(1)),
                None
            );
            assert_eq!(
                remove_with_rotation(
                    &mut tree,
                    initial_index
                        .wrapping_add(ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8)
                        .wrapping_add(1)
                ),
                None
            );

            {
                let mut index = initial_index as u8;
                for epoch in 0..epochs + 1 {
                    assert_eq!(remove_with_rotation(&mut tree, index), Some(epoch));
                    index = index.wrapping_add(1);
                }
            }
        }
    }

    #[test]
    fn manual_compare() {
        assert_eq!(compare_with_rotation(255, 1), Ordering::Less);
        assert_eq!(compare_with_rotation(1, 255), Ordering::Greater);
        assert_eq!(compare_with_rotation(250, 1), Ordering::Less);
        assert_eq!(compare_with_rotation(1, 250), Ordering::Greater);
        assert_eq!(compare_with_rotation(232, 250), Ordering::Less);
        assert_eq!(compare_with_rotation(250, 232), Ordering::Greater);
        assert_eq!(compare_with_rotation(127, 128), Ordering::Less);
        assert_eq!(compare_with_rotation(128, 127), Ordering::Greater);
        assert_eq!(compare_with_rotation(0, 127), Ordering::Less);
        assert_eq!(compare_with_rotation(127, 0), Ordering::Greater);
        assert_eq!(compare_with_rotation(42, 43), Ordering::Less);
        assert_eq!(compare_with_rotation(43, 42), Ordering::Greater);
        assert_eq!(compare_with_rotation(195, 199), Ordering::Less);
        assert_eq!(compare_with_rotation(199, 195), Ordering::Greater);
    }

    #[test]
    fn wrapping_add_compare() {
        for epoch in 0..ORDERED_ROTATABLE_U8_VEC_MAX_SIZE + 1 {
            let mut rng = thread_rng();
            let start_value: u8 = rng.gen::<u8>();
            let size: usize = epoch;

            let mut vec: OrderedRotatableU8Vec<SimpleIndexableU8> = OrderedRotatableU8Vec::new();
            {
                let vec_mut = vec.vec_mut();

                let mut last_tuple_index: u8 = start_value;
                for _ in 0..size {
                    vec_mut.push(SimpleIndexableU8 {
                        index: last_tuple_index,
                    });
                    last_tuple_index = last_tuple_index.wrapping_add(1);
                }
                vec_mut.shuffle(&mut rng);

                vec.order().unwrap();
            }

            {
                let vec_mut = vec.vec_mut();

                let mut last_index: usize = 0;
                let mut last_tuple_index: u8 = start_value;
                for _ in 0..size {
                    assert_eq!(last_tuple_index, vec_mut.get(last_index).unwrap().index);
                    last_tuple_index = last_tuple_index.wrapping_add(1);
                    last_index += 1;
                }
            }
        }
    }
}
