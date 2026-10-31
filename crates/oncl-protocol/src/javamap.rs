//! The iteration order of Java's `HashMap<String, _>`, which org.json's `JSONObject` is backed
//! by: its `toString()` writes keys in this order, not in the order they were put.
//!
//! A key goes into bucket `(h ^ (h >>> 16)) & (capacity - 1)`, `h` its `String.hashCode()`;
//! the map is walked bucket by bucket, and within a bucket in the order the keys went in
//! (a resize splits each bucket keeping that order). The capacity starts at 16 (or at
//! [`table_size_for`] of the size given to the constructor) and doubles once the size
//! exceeds three quarters of it, or when a ninth key lands in one bucket of a table smaller
//! than 64. A bucket of nine keys or more in a table of 64 or more becomes a tree, whose
//! order is not emulated (a debug assertion).
//!
//! The order a bean's properties go in is the JVM's and differs between the original's
//! builds for each OS; callers put them in the order NCALayer shows on Windows 11.

/// `String.hashCode()`: `31 * h + c` over the UTF-16 code units, wrapping.
pub fn string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, unit| {
        h.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// `HashMap.tableSizeFor(n)`: the smallest power of two not below `n`, `1` for `0`.
pub fn table_size_for(n: usize) -> usize {
    n.max(1).next_power_of_two()
}

/// The capacity of `new HashMap()`.
pub const DEFAULT_CAPACITY: usize = 16;

/// A table of more buckets than this never resizes for a crowded bucket: it makes a tree.
const MIN_TREEIFY_CAPACITY: usize = 64;

/// The most keys a bucket holds as a list.
const TREEIFY_THRESHOLD: usize = 8;

/// The bucket of `hash` in a table of `capacity` buckets.
fn bucket(hash: i32, capacity: usize) -> usize {
    let h = hash as u32;
    (h ^ (h >> 16)) as usize & (capacity - 1)
}

/// The keys of a `HashMap` as they go in and out, and the table size they lead to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Table {
    capacity: usize,
    /// The hashes of the keys present, in the order they went in.
    hashes: Vec<i32>,
}

impl Table {
    /// An empty table of `capacity` (a power of two) buckets.
    pub(crate) fn new(capacity: usize) -> Table {
        debug_assert!(capacity.is_power_of_two());
        Table {
            capacity,
            hashes: Vec::new(),
        }
    }

    /// A new key of `hash` goes in last.
    pub(crate) fn push(&mut self, hash: i32) {
        self.hashes.push(hash);
        let at = bucket(hash, self.capacity);
        let crowded = self
            .hashes
            .iter()
            .filter(|h| bucket(**h, self.capacity) == at)
            .count();
        if crowded > TREEIFY_THRESHOLD {
            if self.capacity < MIN_TREEIFY_CAPACITY {
                self.capacity *= 2;
            } else {
                debug_assert!(false, "a HashMap bucket would become a tree");
            }
        }
        if self.hashes.len() > self.capacity / 4 * 3 {
            self.capacity *= 2;
        }
    }

    /// The key at `index` (in the order of going in) goes out. Tables never shrink.
    pub(crate) fn remove(&mut self, index: usize) {
        self.hashes.remove(index);
    }

    /// The indices of the keys present in iteration order.
    pub(crate) fn order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.hashes.len()).collect();
        order.sort_by_key(|&i| bucket(self.hashes[i], self.capacity));
        order
    }
}

/// The order a `HashMap` created with `initial_capacity` buckets (a power of two: 16 for
/// `new HashMap()`, [`table_size_for`] of the size given to `new HashMap(n)`) iterates the
/// distinct `keys` put into it in this order: their indices.
pub fn iteration_order(keys: &[&str], initial_capacity: usize) -> Vec<usize> {
    let mut table = Table::new(initial_capacity);
    for key in keys {
        table.push(string_hash(key));
    }
    table.order()
}
