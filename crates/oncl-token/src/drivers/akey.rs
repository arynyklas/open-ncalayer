//! AKey: an applet of PKCS#11-like objects in a session. A key's certificate, public and
//! private key objects carry the label `nca_<id>_<alias>`; objects with other labels are
//! not ours and are ignored.

use super::util::{gost_public, hex, pkcs1_type1, reversed, rsa_public};
use super::{Driver, KeySlot, wrong_card};
use crate::apdu::Command;
use crate::card::Card;
use crate::error::TokenError;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// Checked on an emulated card only.
pub const HARDWARE_VERIFIED: bool = false;

/// Size of the RSA block the driver pads: RSA-2048 only.
const RSA_BLOCK: usize = 256;

/// Most bytes of the object list and of an object value.
const MAX_STREAM: usize = 65_536;

/// Object types of the list.
const CERTIFICATE: u16 = 1;
const PUBLIC_KEY: u16 = 2;
const PRIVATE_KEY: u16 = 3;

/// Attributes of an object descriptor.
const CKA_KEY_TYPE: u32 = 0x100;
const CKA_ID: u32 = 0x102;

/// The objects of one key.
#[derive(Clone, Debug, Default)]
struct Objects {
    alias: String,
    cert: Option<u16>,
    public: Option<u16>,
    private: Option<(u16, Option<KeyAlg>)>,
}

pub(super) struct AKey {
    token_id: String,
    keys: Vec<(u8, Objects)>,
}

fn token_info() -> Command {
    Command::new(0x80, 0x0A, 0x00, 0x00).with_le(0xB0)
}

/// The attributes `type(4) len(4) value` of a descriptor: the last label (`CKA_ID`) and the
/// key type.
fn attributes(descr: &[u8]) -> (Option<String>, Option<KeyAlg>) {
    let (mut label, mut alg) = (None, None);
    let mut rest = descr;
    while let Some((head, tail)) = rest.split_at_checked(8) {
        let ty = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let Some((value, tail)) = tail.split_at_checked(len) else {
            break;
        };
        match (ty, value) {
            (CKA_ID, _) => label = Some(String::from_utf8_lossy(value).into_owned()),
            (CKA_KEY_TYPE, [0x30, 0x00, 0x00, 0x00]) => alg = Some(KeyAlg::Gost2004),
            (CKA_KEY_TYPE, [0x03, 0x10, 0x32, 0xD4]) => alg = Some(KeyAlg::Gost2015_512),
            (CKA_KEY_TYPE, [0x00, 0x00, 0x00, 0x00]) => alg = Some(KeyAlg::Rsa),
            _ => {}
        }
        rest = tail;
    }
    (label, alg)
}

/// `nca_<id>_<alias>` → id and alias.
fn nca_label(label: &str) -> Option<(u8, &str)> {
    let (id, alias) = label.strip_prefix("nca_")?.split_once('_')?;
    Some((id.parse().ok()?, alias))
}

/// A cursor over the bytes of `80 10` responses, read as needed.
struct Stream<'a, 'c> {
    card: &'a mut Card<'c>,
    buf: Vec<u8>,
    at: usize,
    total: usize,
}

impl Stream<'_, '_> {
    fn take(&mut self, n: usize) -> Result<Vec<u8>, TokenError> {
        while self.buf.len() - self.at < n {
            let more = self.card.expect(
                &Command::new(0x80, 0x10, 0x00, 0x00).with_le(0xFF),
                "list the objects",
            )?;
            self.total += more.len();
            if more.is_empty() || self.total > MAX_STREAM {
                return Err(TokenError::Malformed(
                    "the object list ends early".to_owned(),
                ));
            }
            self.buf.extend(more);
        }
        let out = self.buf[self.at..self.at + n].to_vec();
        self.at += n;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, TokenError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// The whole value of an object: `80 0F <id> FF` until the length the first answer starts
/// with.
fn read_value(card: &mut Card<'_>, id: u16) -> Result<Vec<u8>, TokenError> {
    let [hi, lo] = id.to_be_bytes();
    let cmd = Command::new(0x80, 0x0F, hi, lo).with_le(0xFF);
    let first = card.expect(&cmd, "read an object")?;
    let (len, value) = match first.as_slice() {
        [h, l, rest @ ..] => (usize::from(u16::from_be_bytes([*h, *l])), rest.to_vec()),
        _ => {
            return Err(TokenError::Malformed(
                "an object without a length".to_owned(),
            ));
        }
    };
    if len > MAX_STREAM {
        return Err(TokenError::Malformed(format!("an object of {len} bytes")));
    }
    let mut value = value;
    while value.len() < len {
        let more = card.expect(&cmd, "read an object")?;
        if more.is_empty() {
            return Err(TokenError::Malformed("an object ends early".to_owned()));
        }
        value.extend(more);
    }
    value.truncate(len);
    Ok(value)
}

impl AKey {
    pub(super) fn open(card: &mut Card<'_>) -> Result<AKey, TokenError> {
        card.expect(
            &Command::new(0x00, 0xA4, 0x04, 0x00)
                .with_data([0x77, 0x11, 0xC1, 0x32, 0x09, 0x00, 0x00, 0x00]),
            "select the applet",
        )
        .map_err(wrong_card)?;
        // Whatever ends the operation from here on (another token, a failure before the
        // login), the reset on disconnect closes the session.
        card.reset_on_disconnect();
        card.expect(
            &Command::new(0x80, 0x03, 0x00, 0x00).with_le(5),
            "open a session",
        )
        .map_err(wrong_card)?;
        let info = card.expect(&token_info(), "token information")?;
        let serial = info
            .get(16..32)
            .ok_or_else(|| TokenError::Malformed("short token information".to_owned()))?;
        Ok(AKey {
            token_id: hex(serial),
            keys: Vec::new(),
        })
    }

    fn objects(&self, slot: &KeySlot) -> Result<&Objects, TokenError> {
        self.keys
            .iter()
            .map(|(_, o)| o)
            .find(|o| o.alias == slot.alias)
            .ok_or_else(|| TokenError::Malformed(format!("no objects of key {}", slot.alias)))
    }
}

impl Driver for AKey {
    fn kind(&self) -> TokenKind {
        TokenKind::AKey
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }

    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError> {
        self.check_pin(pin)?;
        let resp = card.transmit(
            &Command::new(0x80, 0x07, 0x00, 0x00)
                .with_data(pin.as_bytes())
                .redacted(),
        )?;
        match resp.sw {
            0x9000 => Ok(()),
            0x9C0C => Err(TokenError::PinBlocked),
            0x9C02 => {
                // The tries left are in the token information.
                let info = card.expect(&token_info(), "token information")?;
                Err(TokenError::WrongPin {
                    tries_left: info.get(85).copied(),
                })
            }
            _ => Err(TokenError::WrongPin { tries_left: None }),
        }
    }

    fn keys(&mut self, card: &mut Card<'_>) -> Result<Vec<KeySlot>, TokenError> {
        let mut stream = Stream {
            card,
            buf: Vec::new(),
            at: 0,
            total: 0,
        };
        let count = stream.u16()?;
        let mut keys: Vec<(u8, Objects)> = Vec::new();
        for _ in 0..count {
            let id = stream.u16()?;
            let ty = stream.u16()?;
            // Unverified on hardware: the meaning of this field is unknown.
            let _ = stream.u16()?;
            let len = usize::from(stream.u16()?);
            let descr = stream.take(len)?;
            let (Some(label), alg) = attributes(&descr) else {
                continue;
            };
            let Some((nca_id, alias)) = nca_label(&label) else {
                continue;
            };
            let at = match keys.iter().position(|(n, _)| *n == nca_id) {
                Some(at) => at,
                None => {
                    keys.push((
                        nca_id,
                        Objects {
                            alias: alias.to_owned(),
                            ..Objects::default()
                        },
                    ));
                    keys.len() - 1
                }
            };
            let objects = &mut keys[at].1;
            match ty {
                CERTIFICATE => objects.cert = Some(id),
                PUBLIC_KEY => objects.public = Some(id),
                PRIVATE_KEY => objects.private = Some((id, alg)),
                _ => {}
            }
        }
        let slots = keys
            .iter()
            .filter_map(|(_, o)| match (o.private, o.public) {
                (Some((id, Some(alg))), Some(_)) => Some(KeySlot {
                    alias: o.alias.clone(),
                    id,
                    alg,
                }),
                _ => {
                    tracing::warn!("AKey: key {} without a usable key pair", o.alias);
                    None
                }
            })
            .collect();
        self.keys = keys;
        Ok(slots)
    }

    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError> {
        let id = self
            .objects(slot)?
            .public
            .ok_or_else(|| TokenError::Malformed(format!("no public key of {}", slot.alias)))?;
        let value = read_value(card, id)?;
        if slot.alg == KeyAlg::Rsa {
            return match value.get(258..258 + RSA_BLOCK) {
                Some(modulus) => rsa_public(modulus),
                None => Err(TokenError::Malformed("a short RSA public key".to_owned())),
            };
        }
        // Unverified on hardware: the curve parameters are taken to fill 328 bytes (256-bit
        // curves) or 648 bytes (512-bit curves) before the point.
        let (skip, n) = if value.len() <= 400 {
            (328, 32)
        } else {
            (648, 64)
        };
        let (Some(x), Some(y)) = (value.get(skip..skip + n), value.get(skip + n..skip + 2 * n))
        else {
            return Err(TokenError::Malformed("a short GOST public key".to_owned()));
        };
        let mut xy = reversed(x);
        xy.extend(reversed(y));
        gost_public(slot.alg, &xy)
    }

    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError> {
        let Some(id) = self.objects(slot)?.cert else {
            return Ok(None);
        };
        // The certificate is stored as DER, not compressed.
        let der = read_value(card, id)?;
        Ok(Some(der).filter(|d| !d.is_empty()))
    }

    fn sign(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
        _alg: SigAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        let (alg, data) = match slot.alg {
            KeyAlg::Rsa => (0x00, pkcs1_type1(digest, RSA_BLOCK)?),
            KeyAlg::Gost2004 => (0x01, reversed(digest)),
            KeyAlg::Gost2015_512 => (0x02, reversed(digest)),
        };
        let mut last = Vec::new();
        for piece in data.chunks(255) {
            last = card.expect(
                &Command::new(0x80, 0x12, alg, slot.id as u8)
                    .with_data(piece)
                    .with_le(0xFF),
                "sign",
            )?;
        }
        Ok(if slot.alg == KeyAlg::Rsa {
            last
        } else {
            reversed(&last)
        })
    }

    fn logout(&mut self, card: &mut Card<'_>) -> Result<(), TokenError> {
        card.expect(&Command::new(0x80, 0x06, 0x00, 0x00), "close the session")
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(nca_label("nca_3_my key"), Some((3, "my key")));
        assert_eq!(nca_label("nca_3_a_b"), Some((3, "a_b")));
        assert_eq!(nca_label("nca_x_a"), None);
        assert_eq!(nca_label("other"), None);
    }

    #[test]
    fn descriptor_attributes() {
        let mut d = Vec::new();
        for (ty, value) in [
            (3u32, &b"label"[..]),
            (CKA_KEY_TYPE, &[0x03, 0x10, 0x32, 0xD4][..]),
            (CKA_ID, &b"first"[..]),
            (CKA_ID, &b"nca_1_x"[..]),
        ] {
            d.extend(ty.to_be_bytes());
            d.extend((value.len() as u32).to_be_bytes());
            d.extend(value);
        }
        assert_eq!(
            attributes(&d),
            (Some("nca_1_x".to_owned()), Some(KeyAlg::Gost2015_512))
        );
        assert_eq!(attributes(&d[..d.len() - 1]).0.as_deref(), Some("first"));
    }
}
