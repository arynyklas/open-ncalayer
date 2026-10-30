//! The OpenNCALayer port of `kz.rating1c.edo` 1.9.5, the module `kz.rating1c.edo.signUtils`:
//! the reflective dispatcher of the official `commonUtils` sample over the class
//! `kz.rating1c.edo.SignUtils` — key information, an owner (BIN/IIN) and validity check, XML,
//! CAdES and raw signatures with the key the user picks.

// Outside wasm32 only the unit tests use the pure parts.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod keyinfo;
#[cfg(target_arch = "wasm32")]
mod port;

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
