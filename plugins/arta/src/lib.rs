//! The OpenNCALayer port of `kz.arta.synergy.signmodule` 6.0 (Arta Synergy), the module
//! `kz.arta.synergy.signmodule`: the reflective dispatcher over
//! `kz.arta.synergy.signmodule.SignService` — a key chosen once (`getKeyInfo`,
//! `getFullKeyInfo`) and kept for the session, then time-stamped CAdES of files and data,
//! raw and ESEDO signatures of documents, and XML signatures with it, without a dialog.

#[cfg(target_arch = "wasm32")]
mod port;

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
