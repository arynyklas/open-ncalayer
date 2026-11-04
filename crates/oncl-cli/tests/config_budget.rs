//! Measured basis of the host-certificate metadata charge (`local.rs`).
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new, Ordering::SeqCst);
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.realloc(ptr, layout, new) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn measured_retained_bytes_per_encoded_certificate_byte_is_far_below_the_charge() {
    let root = oncl_testkit::workspace_root();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for dir in [
        "fixtures/nca/prod",
        "fixtures/nca/test",
        "fixtures/synthetic",
    ] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("der" | "cer")
            ) {
                files.push(path);
            }
        }
    }
    let mut worst = 0f64;
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        let before = LIVE.load(Ordering::SeqCst);
        let cert = oncl_pki::cert::parse(&bytes).unwrap();
        let retained = LIVE.load(Ordering::SeqCst) - before;
        let ratio = retained as f64 / bytes.len() as f64;
        eprintln!(
            "{} der={} retained={retained} ratio={ratio:.2}",
            path.file_name().unwrap().to_string_lossy(),
            bytes.len()
        );
        worst = worst.max(ratio);
        drop(cert);
    }
    eprintln!("files={} worst_ratio={worst:.2}", files.len());
    assert_eq!(files.len(), 21, "fixture set changed");
    // The CLI charges CERTIFICATE_METADATA_FACTOR (16) per encoded byte; the
    // measured worst case must stay at most half of that.
    assert!(worst < 8.0, "measured retained/DER ratio {worst:.2}");
}
