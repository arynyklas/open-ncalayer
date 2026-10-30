//! A PIN sent to a card leaves no copy in freed memory: the allocator of this test binary
//! looks for it in every block freed while the PIN is in use.

use oncl_token::TokenKind;
use oncl_token::apdu::Command;
use oncl_token::backend::{BackendError, Connection, Protocol};
use oncl_token::card::Card;
use oncl_token::drivers::open_driver;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PIN: &str = "7319";

static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicUsize = AtomicUsize::new(0);

/// The system allocator; armed, it counts the freed blocks that hold [`PIN`].
struct Scanning;

// SAFETY: every call is forwarded to the system allocator; a block is only read before it
// is freed.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // SAFETY: the block is allocated with this layout until freed below.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(PIN.len()).any(|w| w == PIN.as_bytes()) {
                FOUND.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: forwarded as is.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// An ID card that accepts everything: 9 bytes of identifier, `9000` to the rest.
struct Accepting;

impl Connection for Accepting {
    fn protocol(&self) -> Protocol {
        Protocol::T1
    }

    fn atr(&self) -> &[u8] {
        &[]
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        if apdu.starts_with(&[0x00, 0xCA, 0xDF, 0x01]) {
            return Ok(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0x90, 0x00]);
        }
        Ok(vec![0x90, 0x00])
    }

    fn reset_on_disconnect(&mut self) {}
}

#[test]
fn pin_copies_are_wiped() {
    let mut conn = Accepting;
    let mut card = Card::new(&mut conn, false);
    let mut driver = open_driver(TokenKind::KzIdCard, &mut card).unwrap();
    ARMED.store(true, Ordering::SeqCst);
    // The PIN padded by the ID card's driver.
    driver.verify_pin(&mut card, PIN).unwrap();
    // A command carrying a PIN, sent and dropped.
    let cmd = Command::new(0x00, 0x20, 0x00, 0x01)
        .with_data(PIN.as_bytes())
        .redacted();
    assert!(card.transmit(&cmd).unwrap().is_ok());
    drop(cmd.clone());
    drop(cmd);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        FOUND.load(Ordering::SeqCst),
        0,
        "freed blocks holding the PIN"
    );
}
