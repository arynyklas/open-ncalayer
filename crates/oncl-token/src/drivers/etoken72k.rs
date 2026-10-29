//! eToken PRO 72K (Java): an applet of named objects. A key's alias is the hex of its
//! object name; on the wire the name goes as `00 <len> <name>`.

use super::util::{gost_public, hex, pkcs1_type1, reversed, rsa_public};
use super::{Driver, KeySlot, wrong_card};
use crate::apdu::Command;
use crate::card::Card;
use crate::error::TokenError;
use crate::gzip::cert_bytes;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// Checked on an emulated card only.
pub const HARDWARE_VERIFIED: bool = false;

/// Size of the RSA block the driver pads: RSA-2048 only.
const RSA_BLOCK: usize = 256;

pub(super) struct EToken72K {
    token_id: String,
}

/// Object name of a key from its alias (the hex of the name).
pub(super) fn object_name(slot: &KeySlot) -> Result<Vec<u8>, TokenError> {
    let name = (0..slot.alias.len())
        .step_by(2)
        .map(|i| {
            slot.alias
                .get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .filter(|n| !n.is_empty() && n.len() <= 255)
        .ok_or_else(|| TokenError::Malformed(format!("the key alias {}", slot.alias)))?;
    let mut out = vec![0x00, name.len() as u8];
    out.extend(name);
    Ok(out)
}

/// The name of an object, up to its NUL; the whole answer when it starts with NUL.
pub(super) fn name_bytes(data: &[u8]) -> &[u8] {
    match data.iter().position(|&b| b == 0) {
        Some(0) | None => data,
        Some(end) => &data[..end],
    }
}

/// The token serial: bytes 9..17 of the token information.
pub(super) fn serial(info: &[u8]) -> Result<String, TokenError> {
    info.get(9..17)
        .map(hex)
        .ok_or_else(|| TokenError::Malformed("short token information".to_owned()))
}

/// The object count `80 12 22 00` gives.
pub(super) fn count(data: &[u8]) -> Result<u16, TokenError> {
    match data {
        [hi, lo, ..] => Ok(u16::from_be_bytes([*hi, *lo])),
        _ => Err(TokenError::Malformed("the object count".to_owned())),
    }
}

/// Probes the key type of an object: `80 12 <ins_p1> 00 <name> 00 <type>`, `00` a GOST key,
/// `03` an RSA key.
pub(super) fn probe(card: &mut Card<'_>, p1: u8, name: &[u8], ty: u8) -> Result<bool, TokenError> {
    let mut data = name.to_vec();
    data.extend([0x00, ty]);
    // Unverified on hardware: the meaning of the last byte (00 GOST, 03 RSA) is inferred.
    Ok(card
        .transmit(&Command::new(0x80, 0x12, p1, 0x00).with_data(data))?
        .is_ok())
}

impl EToken72K {
    pub(super) fn open(card: &mut Card<'_>) -> Result<EToken72K, TokenError> {
        card.expect(
            &Command::new(0x00, 0xA4, 0x04, 0x00)
                .with_data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00]),
            "select the applet",
        )
        .map_err(wrong_card)?;
        card.expect(&Command::new(0x80, 0x15, 0x20, 0x00), "token information")
            .map_err(wrong_card)?;
        let info = card
            .expect(
                &Command::new(0x80, 0x15, 0x10, 0x00).with_le(0x64),
                "token information",
            )
            .map_err(wrong_card)?;
        Ok(EToken72K {
            token_id: serial(&info)?,
        })
    }
}

impl Driver for EToken72K {
    fn kind(&self) -> TokenKind {
        TokenKind::EToken72K
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }

    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError> {
        self.check_pin(pin)?;
        let resp = card.transmit(
            &Command::new(0x80, 0x10, 0x20, 0x00)
                .with_data(pin.as_bytes())
                .redacted(),
        )?;
        // The token gives no count of tries left.
        if resp.is_ok() {
            Ok(())
        } else {
            Err(TokenError::WrongPin { tries_left: None })
        }
    }

    fn keys(&mut self, card: &mut Card<'_>) -> Result<Vec<KeySlot>, TokenError> {
        let n = count(&card.expect(&Command::new(0x80, 0x12, 0x22, 0x00), "count the keys")?)?;
        let mut slots = Vec::new();
        for i in 0..n {
            let data = card.expect(
                &Command::new(0x80, 0x12, 0x21, 0x00).with_data(i.to_be_bytes()),
                "read a key name",
            )?;
            let alias = hex(name_bytes(&data));
            let probe_slot = KeySlot {
                alias,
                id: i,
                alg: KeyAlg::Gost2004,
            };
            let name = object_name(&probe_slot)?;
            let alg = if probe(card, 0x44, &name, 0x00)? {
                KeyAlg::Gost2004
            } else if probe(card, 0x44, &name, 0x03)? {
                KeyAlg::Rsa
            } else {
                // GOST 2015-512 keys are not supported by this token's applet.
                tracing::warn!(
                    "eToken 72K: key {} of an unsupported type",
                    probe_slot.alias
                );
                continue;
            };
            slots.push(KeySlot { alg, ..probe_slot });
        }
        Ok(slots)
    }

    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError> {
        let name = object_name(slot)?;
        if slot.alg != KeyAlg::Rsa {
            let mut xy = Vec::with_capacity(64);
            for p1 in [0x21, 0x24] {
                let half = card.expect(
                    &Command::new(0x80, 0x11, p1, 0x00).with_data(name.clone()),
                    "read public key",
                )?;
                let half = half
                    .get(..32)
                    .ok_or_else(|| TokenError::Malformed("a short public key".to_owned()))?;
                xy.extend(reversed(half));
            }
            return gost_public(slot.alg, &xy);
        }
        let mut data = vec![0x00, 0x00];
        data.extend(&name);
        let bits = count(&card.expect(
            &Command::new(0x80, 0x12, 0x47, 0x00).with_data(data.clone()),
            "read public key",
        )?)?;
        let len = usize::from(bits) / 8;
        if len == 0 || len % 32 != 0 {
            return Err(TokenError::Malformed(format!("an RSA key of {bits} bits")));
        }
        let mut modulus = Vec::with_capacity(len);
        for off in (0..len).step_by(32) {
            data[..2].copy_from_slice(&(off as u16).to_be_bytes());
            let block = card.expect(
                &Command::new(0x80, 0x12, 0x47, 0x01).with_data(data.clone()),
                "read public key",
            )?;
            modulus.extend(
                block
                    .get(..32)
                    .ok_or_else(|| TokenError::Malformed("a short modulus block".to_owned()))?,
            );
        }
        rsa_public(&modulus)
    }

    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError> {
        let resp =
            card.transmit(&Command::new(0x80, 0x12, 0x43, 0x00).with_data(object_name(slot)?))?;
        if !resp.is_ok() {
            return Ok(None);
        }
        let len = count(&card.expect(
            &Command::new(0x80, 0x12, 0x41, 0x00).with_data([0x00, 0x00]),
            "read the certificate",
        )?)?;
        let len = usize::from(len);
        if len == 0 {
            return Ok(None);
        }
        if len > crate::MAX_GZ_CERT {
            return Err(TokenError::Malformed(format!(
                "a certificate of {len} bytes"
            )));
        }
        let mut raw = Vec::with_capacity(len);
        while raw.len() < len {
            let mut data = vec![0x00, 0x20];
            data.extend((raw.len() as u16).to_be_bytes());
            let chunk = card.expect(
                &Command::new(0x80, 0x12, 0x41, 0x00).with_data(data),
                "read the certificate",
            )?;
            if chunk.is_empty() {
                return Err(TokenError::Malformed("a short certificate".to_owned()));
            }
            raw.extend(chunk);
        }
        raw.truncate(len);
        cert_bytes(&raw).map(Some)
    }

    fn sign(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
        _alg: SigAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        let name = object_name(slot)?;
        if slot.alg != KeyAlg::Rsa {
            let mut data = name;
            data.extend(reversed(digest));
            let first = card.expect(
                &Command::new(0x80, 0x14, 0x10, 0x00).with_data(data),
                "sign",
            )?;
            let second = card.expect(&Command::new(0x80, 0x11, 0x25, 0x00), "sign")?;
            let (Some(r), Some(s)) = (first.get(..32), second.get(..32)) else {
                return Err(TokenError::Malformed("a short signature".to_owned()));
            };
            // Unverified on hardware: the card is taken to answer r_BE, then s_BE.
            let mut sig = reversed(r);
            sig.extend(reversed(s));
            return Ok(sig);
        }
        let block = pkcs1_type1(digest, RSA_BLOCK)?;
        for (i, piece) in block.chunks(32).enumerate() {
            let mut data = vec![0x00, (i * 32) as u8];
            data.extend(piece);
            card.expect(
                &Command::new(0x80, 0x12, 0x49, 0x00).with_data(data),
                "sign",
            )?;
        }
        let mut data = vec![0x01, 0x00];
        data.extend(&name);
        card.expect(
            &Command::new(0x80, 0x14, 0x52, 0x77).with_data(data),
            "sign",
        )?;
        let mut sig = Vec::with_capacity(RSA_BLOCK);
        for off in (0..RSA_BLOCK).step_by(32) {
            let piece = card.expect(
                &Command::new(0x80, 0x12, 0x48, 0x00).with_data((off as u16).to_be_bytes()),
                "sign",
            )?;
            sig.extend(
                piece
                    .get(..32)
                    .ok_or_else(|| TokenError::Malformed("a short signature".to_owned()))?,
            );
        }
        Ok(sig)
    }

    fn logout(&mut self, _card: &mut Card<'_>) -> Result<(), TokenError> {
        // No logout command: the reset at disconnect ends the verification.
        Ok(())
    }
}
