//! The emulator's configuration file: readers and the cards in them, as TOML.
//!
//! ```toml
//! [[reader]]
//! name = "OpenNCALayer Emulated Kaztoken 0"
//! kind = "AKKaztokenStore"        # storage name; no kind: an empty reader
//! pin = "123456"
//! tries = 10                      # optional, 10
//! protocol = "T1"                 # optional, "T0" or "T1"; the family's usual one
//! keys = [{ p12 = "fixtures/synthetic/user-gost2015-sign.p12", password = "Qwerty12" }]
//! # AKKZIDCardStore only:
//! id_card = { iin = "…", last_name = "…", first_name = "…", middle_name = "…" }
//! ```
//!
//! Optional as well: `serial` (16 hex digits), `atr_index`, `fixed_k` (hex, the GOST nonce).
//! Key paths are relative to the base directory given.

use super::{CardSpec, EmuKey};
use crate::backend::Protocol;
use crate::drivers::IdCardInfo;
use crate::kind::TokenKind;
use serde::Deserialize;
use std::path::Path;

/// A reader of the configuration and its card.
#[derive(Clone, Debug)]
pub struct ReaderConfig {
    /// Reader name.
    pub name: String,
    /// The card in it; `None` for an empty reader.
    pub card: Option<CardSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    reader: Vec<ReaderToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderToml {
    name: String,
    kind: Option<String>,
    pin: Option<String>,
    tries: Option<u8>,
    protocol: Option<String>,
    serial: Option<String>,
    atr_index: Option<usize>,
    fixed_k: Option<String>,
    #[serde(default)]
    keys: Vec<KeyToml>,
    id_card: Option<IdCardToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyToml {
    p12: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdCardToml {
    iin: String,
    last_name: String,
    first_name: String,
    middle_name: Option<String>,
}

fn hex_bytes(field: &str, text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("{field}: an odd number of hex digits"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(|| format!("{field}: not hex: {text:?}"))
        })
        .collect()
}

/// Reads a configuration; key paths are relative to `base`.
///
/// # Errors
///
/// Invalid TOML or fields, an unknown storage name or protocol, a key file that cannot be
/// read.
pub fn read_config(text: &str, base: &Path) -> Result<Vec<ReaderConfig>, String> {
    let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
    file.reader
        .into_iter()
        .map(|r| {
            let card = r
                .kind
                .as_deref()
                .map(|kind| spec(&r, kind, base))
                .transpose()?;
            Ok(ReaderConfig { name: r.name, card })
        })
        .collect()
}

fn spec(r: &ReaderToml, kind: &str, base: &Path) -> Result<CardSpec, String> {
    let name = &r.name;
    let kind = TokenKind::from_storage_name(kind)
        .ok_or_else(|| format!("{name}: unknown storage {kind:?}"))?;
    let pin = r.pin.as_deref().ok_or_else(|| format!("{name}: no pin"))?;
    let keys = r
        .keys
        .iter()
        .map(|k| EmuKey::load(&base.join(&k.p12), &k.password))
        .collect::<Result<Vec<_>, _>>()?;
    let mut spec = CardSpec::new(kind, pin, keys);
    if let Some(tries) = r.tries {
        spec.tries = tries;
        spec.max_tries = tries;
    }
    match r.protocol.as_deref() {
        None => {}
        Some("T0") => spec.protocol = Protocol::T0,
        Some("T1") => {
            spec.protocol = Protocol::T1;
            spec.t0_quirks = false;
        }
        Some(other) => return Err(format!("{name}: unknown protocol {other:?}")),
    }
    if spec.protocol == Protocol::T0 {
        spec.t0_quirks = true;
    }
    if let Some(serial) = &r.serial {
        spec.serial = hex_bytes("serial", serial)?
            .try_into()
            .map_err(|_| format!("{name}: the serial is 8 bytes"))?;
    }
    if let Some(index) = r.atr_index {
        let count = crate::ATRS.iter().filter(|(k, _)| *k == kind).count();
        if index >= count {
            return Err(format!("{name}: {kind:?} has {count} ATRs"));
        }
        spec.atr_index = index;
    }
    if let Some(k) = &r.fixed_k {
        spec.fixed_k = Some(hex_bytes("fixed_k", k)?);
    }
    if let Some(id) = &r.id_card {
        if kind != TokenKind::KzIdCard {
            return Err(format!("{name}: id_card on a {}", kind.storage_name()));
        }
        spec.id_card = Some(IdCardInfo {
            iin: id.iin.clone(),
            last_name: id.last_name.clone(),
            first_name: id.first_name.clone(),
            middle_name: id.middle_name.clone(),
        });
    }
    Ok(spec)
}
