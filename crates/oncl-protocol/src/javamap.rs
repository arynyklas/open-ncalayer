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
#[derive(Clone, Debug)]
pub(crate) struct Table {
    capacity: usize,
    /// The hashes of the keys present, in the order they went in.
    hashes: Vec<i32>,
    /// The keys in each of the `capacity` buckets (empty before the first key), counted
    /// again when the table grows.
    counts: Vec<u32>,
}

/// Tables are equal by their size and keys; the counts follow from them.
impl PartialEq for Table {
    fn eq(&self, other: &Table) -> bool {
        self.capacity == other.capacity && self.hashes == other.hashes
    }
}

impl Eq for Table {}

impl Table {
    /// An empty table of `capacity` (a power of two) buckets.
    pub(crate) fn new(capacity: usize) -> Table {
        debug_assert!(capacity.is_power_of_two());
        Table {
            capacity,
            hashes: Vec::new(),
            counts: Vec::new(),
        }
    }

    /// A new key of `hash` goes in last.
    pub(crate) fn push(&mut self, hash: i32) {
        if self.counts.is_empty() {
            self.counts = vec![0; self.capacity];
        }
        self.hashes.push(hash);
        let at = bucket(hash, self.capacity);
        self.counts[at] += 1;
        let capacity = self.capacity;
        if self.counts[at] as usize > TREEIFY_THRESHOLD {
            if self.capacity < MIN_TREEIFY_CAPACITY {
                self.capacity *= 2;
            } else {
                debug_assert!(false, "a HashMap bucket would become a tree");
            }
        }
        if self.hashes.len() > self.capacity / 4 * 3 {
            self.capacity *= 2;
        }
        if self.capacity != capacity {
            self.counts = vec![0; self.capacity];
            for &h in &self.hashes {
                self.counts[bucket(h, self.capacity)] += 1;
            }
        }
    }

    /// The key at `index` (in the order of going in) goes out. Tables never shrink.
    pub(crate) fn remove(&mut self, index: usize) {
        let hash = self.hashes.remove(index);
        self.counts[bucket(hash, self.capacity)] -= 1;
    }

    /// The indices of the keys present in iteration order: bucket by bucket, in the order
    /// they went in within each.
    pub(crate) fn order(&self) -> Vec<usize> {
        if self.hashes.is_empty() {
            return Vec::new();
        }
        // Where each bucket starts in the order.
        let mut next: Vec<usize> = Vec::with_capacity(self.capacity);
        let mut start = 0;
        for &count in &self.counts {
            next.push(start);
            start += count as usize;
        }
        let mut order = vec![0; self.hashes.len()];
        for (i, &h) in self.hashes.iter().enumerate() {
            let at = &mut next[bucket(h, self.capacity)];
            order[*at] = i;
            *at += 1;
        }
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
