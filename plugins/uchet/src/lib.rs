//! The OpenNCALayer port of `kz.uchet.signUtil` 1.5, the module
//! `kz.uchet.signUtil.commonUtils`: the reflective dispatcher over
//! `kz.uchet.signUtil.CommonUtils` — XML signatures, file choosers, CMS verification
//! reports, and time-stamped CAdES of files with the key of a dialog or, behind uchet.kz's
//! license check, of a key file the page names.

#[cfg(target_arch = "wasm32")]
mod port;
#[cfg(target_arch = "wasm32")]
mod texts;

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
