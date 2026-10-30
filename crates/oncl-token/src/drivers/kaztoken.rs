//! Kaztoken: no applet to select; keys are files under `1000/1000/600x/00<id>`, their aliases
//! in the map file `1000/1010/1010`.

use super::util::{hex, pkcs1_type1, reversed};
use super::{Driver, KeySlot, wrong_card};
use crate::apdu::Command;
use crate::card::Card;
use crate::error::TokenError;
use crate::gzip::cert_bytes;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// Checked on an emulated card only.
pub const HARDWARE_VERIFIED: bool = false;

pub(super) struct Kaztoken {
    token_id: String,
}

fn logout() -> Command {
    Command::new(0x80, 0x40, 0x00, 0x00)
}

fn verify() -> Command {
    Command::new(0x00, 0x20, 0x00, 0x02)
}

/// SELECT by path from the MF, the FCP back.
fn select_path(path: &[u8]) -> Command {
    Command::new(0x00, 0xA4, 0x08, 0x04).with_data(path.to_vec())
}

/// Path of a key file: `1000/1000/<dir>/00<id>`.
fn key_file(dir: u8, slot: &KeySlot) -> Vec<u8> {
    vec![0x10, 0x00, 0x10, 0x00, 0x60, dir, 0x00, slot.id as u8]
}

/// Size of an EF from its FCP `62 L 80 02 <size>`.
fn fcp_size(fcp: &[u8]) -> Result<usize, TokenError> {
    match fcp {
        [0x62, _, 0x80, 0x02, hi, lo, ..] => Ok(usize::from(u16::from_be_bytes([*hi, *lo]))),
        _ => Err(TokenError::Malformed(
            "a file control template without a size".to_owned(),
        )),
    }
}

/// Key type from the FCP of the private key file: `85 06 03` GOST 2004, `85 06 23` RSA,
/// `85 06 43` GOST 2015-512.
fn key_alg(fcp: &[u8]) -> Option<KeyAlg> {
    fcp.windows(3).find_map(|w| match w {
        [0x85, 0x06, 0x03] => Some(KeyAlg::Gost2004),
        [0x85, 0x06, 0x23] => Some(KeyAlg::Rsa),
        [0x85, 0x06, 0x43] => Some(KeyAlg::Gost2015_512),
        _ => None,
    })
}

/// The map file: header `01 00 00 10`, then `<id> <alias> 00` per key.
fn parse_map(map: &[u8]) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    let mut rest = map.get(4..).unwrap_or_default();
    while let [id, tail @ ..] = rest {
        if *id == 0 {
            break;
        }
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        out.push((*id, String::from_utf8_lossy(&tail[..end]).into_owned()));
        rest = tail.get(end + 1..).unwrap_or_default();
    }
    out
}

impl Kaztoken {
    pub(super) fn open(card: &mut Card<'_>) -> Result<Kaztoken, TokenError> {
        let data = card
            .expect(
                &Command::new(0x00, 0xCA, 0x01, 0x81).with_le(0xFF),
                "get serial number",
            )
            .map_err(wrong_card)?;
        let serial = data
            .get(4..)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| TokenError::Malformed("a short serial number".to_owned()))?;
        Ok(Kaztoken {
            token_id: hex(serial),
        })
    }

    fn select_file(
        &mut self,
        card: &mut Card<'_>,
        path: &[u8],
    ) -> Result<Option<Vec<u8>>, TokenError> {
        let resp = card.transmit(&select_path(path).with_le(256))?;
        match resp.sw {
            0x9000 => Ok(Some(resp.data)),
            0x6A82 => Ok(None),
            sw => Err(TokenError::Card {
                op: "select file",
                sw,
            }),
        }
    }

    fn modulus(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<Vec<u8>, TokenError> {
        let le = if slot.alg == KeyAlg::Rsa { 256 } else { 0xFF };
        card.expect(
            &Command::new(0x00, 0x46, 0x81, slot.id as u8).with_le(le),
            "read public key",
        )
    }
}

impl Driver for Kaztoken {
    fn kind(&self) -> TokenKind {
        TokenKind::Kaztoken
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }

    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError> {
        self.check_pin(pin)?;
        card.transmit(&logout())?;
        let resp = card.transmit(&verify().with_data(pin.as_bytes()).redacted())?;
        if resp.is_ok() {
            return Ok(());
        }
        let status = card.transmit(&verify())?;
        Err(match status.sw {
            0x6983 => TokenError::PinBlocked,
            sw if sw >> 8 == 0x63 => TokenError::WrongPin {
                tries_left: Some(status.sw2() & 0x0F),
            },
            _ => TokenError::WrongPin { tries_left: None },
        })
    }

    fn pin_tries(&mut self, card: &mut Card<'_>) -> Result<Option<u8>, TokenError> {
        // VERIFY without data asks for the PIN's state.
        let status = card.transmit(&verify())?;
        Ok(match status.sw {
            0x6983 => Some(0),
            sw if sw >> 8 == 0x63 => Some(status.sw2() & 0x0F),
            _ => None,
        })
    }

    fn keys(&mut self, card: &mut Card<'_>) -> Result<Vec<KeySlot>, TokenError> {
        // The map file is only read: a token without one has no keys, and none is created.
        let found = card.transmit(&select_path(&[0x10, 0x00, 0x10, 0x10, 0x10, 0x10]))?;
        match found.sw {
            0x9000 => {}
            0x6A82 => return Ok(Vec::new()),
            sw => {
                return Err(TokenError::Card {
                    op: "select the key map",
                    sw,
                });
            }
        }
        let fcp = card.expect(
            &Command::new(0x00, 0xA4, 0x00, 0x04)
                .with_data([0x10, 0x10])
                .with_le(0xFF),
            "select the key map",
        )?;
        let size = fcp_size(&fcp)?;
        let map = card.read_binary(0, size)?;
        let mut slots = Vec::new();
        for (id, alias) in parse_map(&map) {
            let probe = KeySlot {
                alias,
                id: u16::from(id),
                alg: KeyAlg::Rsa,
            };
            let Some(fcp) = self.select_file(card, &key_file(0x02, &probe))? else {
                tracing::warn!("Kaztoken: no private key file for alias {}", probe.alias);
                continue;
            };
            match key_alg(&fcp) {
                Some(alg) => slots.push(KeySlot { alg, ..probe }),
                None => tracing::warn!("Kaztoken: unknown key type for alias {}", probe.alias),
            }
        }
        Ok(slots)
    }

    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError> {
        let data = self.modulus(card, slot)?;
        match slot.alg {
            // The card gives the point as X_LE ‖ Y_LE already.
            KeyAlg::Gost2004 | KeyAlg::Gost2015_512 => super::util::gost_public(slot.alg, &data),
            // The modulus comes little-endian.
            KeyAlg::Rsa => super::util::rsa_public(&reversed(&data)),
        }
    }

    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError> {
        let Some(fcp) = self.select_file(card, &key_file(0x04, slot))? else {
            return Ok(None);
        };
        let size = fcp_size(&fcp)?;
        if size == 0 {
            return Ok(None);
        }
        if size > crate::MAX_GZ_CERT {
            return Err(TokenError::Malformed(format!(
                "a certificate file of {size} bytes"
            )));
        }
        cert_bytes(&card.read_binary(0, size)?).map(Some)
    }

    fn sign(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
        alg: SigAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        let id = slot.id as u8;
        if slot.alg != KeyAlg::Rsa {
            // MSE SET with tag 91, then PSO COMPUTE DIGITAL SIGNATURE of the hash as is; the
            // signature comes as r_LE ‖ s_LE.
            card.expect(
                &Command::new(0x00, 0x22, 0x41, 0xB6).with_data([0x91, 0x01, 0x40, 0x84, 0x01, id]),
                "set the signing key",
            )?;
            return card.expect(
                &Command::new(0x00, 0x2A, 0x9E, 0x9A)
                    .with_data(digest)
                    .with_le(0xFF),
                "sign",
            );
        }
        debug_assert!(matches!(alg, SigAlg::RsaSha256 | SigAlg::RsaSha1));
        card.expect(
            &Command::new(0x00, 0x22, 0x41, 0xB6).with_data([0x95, 0x01, 0x40, 0x84, 0x01, id]),
            "set the signing key",
        )?;
        let modulus_len = self.modulus(card, slot)?.len();
        // Unverified on hardware: the card takes the whole PKCS#1 block little-endian, in a
        // command chain (CLA 10) of the reversed DigestInfo and then the reversed padding.
        let block = reversed(&pkcs1_type1(digest, modulus_len)?);
        let (digest_info, padding) = block.split_at(digest.len());
        card.expect(
            &Command::new(0x10, 0x2A, 0x9E, 0x9A).with_data(digest_info),
            "sign",
        )?;
        let mut pieces = padding.chunks(255).peekable();
        while let Some(piece) = pieces.next() {
            if pieces.peek().is_some() {
                card.expect(
                    &Command::new(0x10, 0x2A, 0x9E, 0x9A).with_data(piece),
                    "sign",
                )?;
            } else {
                let sig = card.expect(
                    &Command::new(0x00, 0x2A, 0x9E, 0x9A)
                        .with_data(piece)
                        .with_le(modulus_len.min(256) as u32),
                    "sign",
                )?;
                return Ok(reversed(&sig));
            }
        }
        unreachable!("the padding is at least 11 bytes")
    }

    fn logout(&mut self, card: &mut Card<'_>) -> Result<(), TokenError> {
        card.expect(&logout(), "log out").map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_parsing() {
        let map = b"\x01\x00\x00\x10\x01first\x00\x02second\x00\x00\x00";
        assert_eq!(
            parse_map(map),
            [(1, "first".to_owned()), (2, "second".to_owned())]
        );
        assert!(parse_map(&[1, 0, 0, 0x10]).is_empty());
        assert_eq!(
            parse_map(b"\x01\x00\x00\x10\x05cut"),
            [(5, "cut".to_owned())]
        );
    }
}
