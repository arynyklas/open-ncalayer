//! The plugin ports under the manual window's call path (docs/design/manual-plugins.md 4.2,
//! docs/design/manual-plugins-inventory.md): every declared `[[operations]]` of a port is run
//! with its REAL wasm module and a REAL synthetic key, and what it signs is checked by tools
//! that are not OpenNCALayer's signer. A declaration that differs from what the module really
//! passes to the key import is refused by Core (`options-mismatch`), so a run is the proof of
//! the declaration.
//!
//! All tests are `#[ignore]`: they need the built modules. Run them with
//! `cargo xtask plugin-ports-manual` (builds the wasm, runs this file); see
//! docs/dev/plugins-manual-tests.md. One module per wave of ports; the harness is
//! `support/ports.rs`.
#![allow(dead_code)]
#[path = "support/ports.rs"]
mod ports;

// Wave 1: rating1c, fhs, esf-osdkz (no declared operation: see the inventory's correction).
#[path = "plugin_ports_manual/esf_osdkz.rs"]
mod esf_osdkz;
#[path = "plugin_ports_manual/fhs.rs"]
mod fhs;
#[path = "plugin_ports_manual/rating1c.rs"]
mod rating1c;
// The limits of the desktop's manual window (MP7b).
#[path = "plugin_ports_manual/limits.rs"]
mod limits;
// The rule for key operations without a network.
#[path = "plugin_ports_manual/network.rs"]
mod network;
