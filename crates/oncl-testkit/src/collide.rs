//! Keys an attacker who knows a hash function chooses so that they all collide: the input of
//! the tests that a hashed structure holding a page's keys has no such function to know.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// `count` distinct keys (`c<number>`) whose `hash` has its low `bits` bits zero, so that a
/// table of at most `2^bits` buckets that indexes by those bits gives them all one home
/// bucket. Found by trying numbers in turn on every core: about `count << bits` hashes.
pub fn colliding_keys<H>(hash: H, count: usize, bits: u32) -> Vec<String>
where
    H: Fn(&str) -> u64 + Sync,
{
    let mask = (1u64 << bits) - 1;
    let found = Mutex::new(Vec::with_capacity(count));
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                // A block of numbers at a time: the counter is not the bottleneck.
                const BLOCK: usize = 1 << 12;
                while found.lock().expect("no panic holds the lock").len() < count {
                    let from = next.fetch_add(BLOCK, Ordering::Relaxed);
                    let hits: Vec<(usize, String)> = (from..from + BLOCK)
                        .filter_map(|n| {
                            let key = format!("c{n}");
                            (hash(&key) & mask == 0).then_some((n, key))
                        })
                        .collect();
                    found.lock().expect("no panic holds the lock").extend(hits);
                }
            });
        }
    });
    let mut keys = found.into_inner().expect("no panic holds the lock");
    keys.sort_by_key(|(n, _)| *n);
    keys.into_iter().take(count).map(|(_, key)| key).collect()
}
