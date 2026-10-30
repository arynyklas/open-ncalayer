//! The OpenNCALayer port of `kz.gov.pki.cms.NLDocSignerModule` 1.2.1 (ezSigner), the module
//! `kz.gov.pki.cms.CMSSignUtil`: the reflective dispatcher's variant with the page's `lang`
//! over `kz.gov.pki.cms.CMSSignUtil` — file and folder choosers, and a time-stamped CAdES of
//! a local file the page names, written next to it.

// Outside wasm32 only the unit tests use the pure parts.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

#[cfg(target_arch = "wasm32")]
mod port;
mod texts;

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
