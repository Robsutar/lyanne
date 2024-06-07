use std::{cmp::Ordering, io};

pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE: usize = (std::mem::size_of::<u8>() * 255) / 2;
pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8: u8 = ORDERED_ROTATABLE_U8_VEC_MAX_SIZE as u8;

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

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};

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
    fn manual_compare() {
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
