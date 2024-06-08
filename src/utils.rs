use std::{cmp::Ordering, collections::BTreeMap, io};

pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE: usize = (std::mem::size_of::<u8>() * 255) / 2;
pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U8: u8 = ORDERED_ROTATABLE_U8_VEC_MAX_SIZE as u8;
pub const ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U16: u16 = ORDERED_ROTATABLE_U8_VEC_MAX_SIZE as u16;

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
    if let Some((last, _)) = tree.last_key_value() {
        let large_index = index as u16;
        if *last >= 256
            && *tree.first_key_value().unwrap().0 - large_index
                > ORDERED_ROTATABLE_U8_VEC_MAX_SIZE_U16
        {
            return tree.remove(&(large_index.wrapping_add(256)));
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
    fn rotation_check() {
        let large: MessagePartLargeId = 255;
        let next: MessagePartId = ((large + 1) % 256) as MessagePartId;
        assert_eq!(0, next);
    }

    #[test]
    fn remove_with_rotation_check() {
        let initial_indexes: Vec<u8> = vec![0, 45, 99, 122, 126, 127, 144, 200, 240, 254, 255];

        for initial_index in initial_indexes {
            let mut tree: BTreeMap<u16, usize> = BTreeMap::new();

            {
                let mut index = initial_index as u16;
                for epoch in 0..ORDERED_ROTATABLE_U8_VEC_MAX_SIZE + 1 {
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
                for epoch in 0..ORDERED_ROTATABLE_U8_VEC_MAX_SIZE + 1 {
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
