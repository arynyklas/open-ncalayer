//! The OpenNCALayer port of `kz.metadoc.NCAModule` 1.7 (Metadoc), the module
//! `kz.metadoc.NCAModule`: its own `{"method":…}` switch over top-level fields — key
//! information, a key file chooser, XML signatures and, for any other method, an ESEDO CMS
//! with the key file the page names and its password (or one the user types), an OCSP
//! answer as signingTime, the whole `TimeStampResp` as the time-stamp attribute, checked
//! before it is given out.

#[cfg(target_arch = "wasm32")]
mod port;

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
