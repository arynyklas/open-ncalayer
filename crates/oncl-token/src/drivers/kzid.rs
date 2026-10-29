//! The Kazakhstan ID card: no applet to select; key pairs are security data objects in DF
//! `0101` (RSA references `87`–`8A`, GOST 2015-512 references `01`–`02`), certificates in
//! DF `0801`, the IIN in EF `0301`, the holder's name in the ICAO data group 11.

use super::util::{gost_public, hex, reverse_halves, reversed, rsa_public};
use super::{Driver, IdCardInfo, KeySlot, wrong_card};
use crate::apdu::Command;
use crate::card::Card;
use crate::error::TokenError;
use crate::gzip::cert_bytes;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// Checked on an emulated card only.
pub const HARDWARE_VERIFIED: bool = false;

/// Key pairs: references and alias prefixes; a pair is listed when both public keys read.
const PAIRS: [[(u8, &str); 2]; 3] = [
    [(0x87, "RSA1"), (0x88, "RSA2")],
    [(0x89, "RSA3"), (0x8A, "RSA4")],
    [(0x01, "GOST1"), (0x02, "GOST2")],
];

pub(super) struct KzIdCard {
    token_id: String,
    public: Vec<(u16, PublicKey)>,
}

fn select(p1: u8, fid: &[u8]) -> Command {
    Command::new(0x00, 0xA4, p1, 0x0C).with_data(fid.to_vec())
}

fn select_mf(card: &mut Card<'_>) -> Result<(), TokenError> {
    card.expect(&select(0x00, &[0x3F, 0x00]), "select the MF")
        .map(drop)
}

fn select_keys(card: &mut Card<'_>) -> Result<(), TokenError> {
    card.expect(&select(0x01, &[0x01, 0x01]), "select the keys")
        .map(drop)
}

/// RSA public key: the 256-byte modulus after a 15-byte header.
fn rsa_modulus(data: &[u8]) -> Result<PublicKey, TokenError> {
    // Unverified on hardware: the response header is taken as 15 bytes long.
    match data.get(15..15 + 256) {
        Some(modulus) => rsa_public(modulus),
        None => Err(TokenError::Malformed(format!(
            "an RSA public key of {} bytes; only RSA-2048 is supported",
            data.len().saturating_sub(15)
        ))),
    }
}

/// GOST 2015-512 public key: `X_BE ‖ Y_BE` after a 12-byte header.
fn gost_point(data: &[u8]) -> Result<PublicKey, TokenError> {
    // Unverified on hardware: the response header is taken as 12 bytes long.
    let xy = data.get(12..12 + 128).ok_or_else(|| {
        TokenError::Malformed(format!("a GOST public key of {} bytes", data.len()))
    })?;
    gost_public(KeyAlg::Gost2015_512, &reverse_halves(xy))
}

fn read_public(card: &mut Card<'_>, reference: u8) -> Result<PublicKey, TokenError> {
    select_mf(card)?;
    select_keys(card)?;
    if reference & 0x80 != 0 {
        let mut data = vec![
            0x4D,
            0x09,
            0xFF,
            0xA0,
            reference & 0x7F,
            0x05,
            0x7F,
            0x49,
            0x02,
        ];
        data.extend([0x81, 0x00]);
        let resp = card.expect(
            &Command::new(0x00, 0xCB, 0x3F, 0xFF).with_data(data),
            "read public key",
        )?;
        rsa_modulus(&resp)
    } else {
        let data = vec![
            0x4D, 0x09, 0xFF, 0xA2, reference, 0x05, 0x7F, 0x4E, 0x02, 0x86, 0x00,
        ];
        let resp = card.expect(
            &Command::new(0x00, 0xCB, 0x3F, 0xFF).with_data(data),
            "read public key",
        )?;
        gost_point(&resp)
    }
}

/// The certificate EF of a key: `0101` for the first key of each pair, `0102` for the
/// second (an RSA and a GOST key share one).
fn cert_ef(reference: u8) -> u8 {
    match reference {
        0x87 | 0x89 | 0x01 => 0x01,
        _ => 0x02,
    }
}

/// The value of the first `tag` (two bytes, one-byte length) in `data` from `from`, and
/// where it ends.
fn find_tag(data: &[u8], from: usize, tag: [u8; 2]) -> Option<(String, usize)> {
    let at = from + data.get(from..)?.windows(2).position(|w| w == tag)?;
    let len = usize::from(*data.get(at + 2)?);
    let value = data.get(at + 3..at + 3 + len)?;
    Some((String::from_utf8_lossy(value).into_owned(), at + 3 + len))
}

/// The holder's names in data group 11: the last name in `5F0E`, then the middle and
/// first names in two `5F0F`.
fn parse_dg11(data: &[u8]) -> Result<(String, String, Option<String>), TokenError> {
    let malformed = || TokenError::Malformed("data group 11".to_owned());
    if data.first() != Some(&0x6B)
        || data.len() != usize::from(*data.get(1).ok_or_else(malformed)?) + 2
    {
        return Err(malformed());
    }
    let list = data
        .windows(5)
        .position(|w| w == [0x5F, 0x0E, 0x5F, 0x2B, 0xA0])
        .ok_or_else(malformed)?
        + 5;
    let (last, at) = find_tag(data, list, [0x5F, 0x0E]).ok_or_else(malformed)?;
    let (second, at) = find_tag(data, at, [0x5F, 0x0F]).ok_or_else(malformed)?;
    // Unverified against the original: a holder without a middle name is taken to have a
    // single other name, the first name.
    Ok(match find_tag(data, at, [0x5F, 0x0F]) {
        Some((first, _)) => (last, first, Some(second).filter(|m| !m.is_empty())),
        None => (last, second, None),
    })
}

/// The holder of the ID card in `card`, read without the PIN: the IIN (EF `0301`) and the
/// names (data group 11).
///
/// # Errors
///
/// Card and transport errors, [`TokenError::Malformed`] for unreadable data.
pub fn read_id_card(card: &mut Card<'_>) -> Result<IdCardInfo, TokenError> {
    select_mf(card)?;
    card.expect(&select(0x02, &[0x03, 0x01]), "select the IIN")?;
    let iin = card.expect(
        &Command::new(0x00, 0xB0, 0x00, 0x00).with_le(12),
        "read the IIN",
    )?;
    if iin.len() != 12 || !iin.iter().all(u8::is_ascii_digit) {
        return Err(TokenError::Malformed("the IIN".to_owned()));
    }
    card.expect(
        &Command::new(0x00, 0xA4, 0x04, 0x0C).with_data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]),
        "select the travel document",
    )?;
    let dg11 = card.expect(
        &Command::new(0x00, 0xB0, 0x8B, 0x00).with_le(256),
        "read data group 11",
    )?;
    let (last_name, first_name, middle_name) = parse_dg11(&dg11)?;
    Ok(IdCardInfo {
        iin: String::from_utf8_lossy(&iin).into_owned(),
        last_name,
        first_name,
        middle_name,
    })
}

impl KzIdCard {
    pub(super) fn open(card: &mut Card<'_>) -> Result<KzIdCard, TokenError> {
        let id = card
            .expect(
                &Command::new(0x00, 0xCA, 0xDF, 0x01).with_le(9),
                "get the card number",
            )
            .map_err(wrong_card)?;
        Ok(KzIdCard {
            token_id: hex(&id),
            public: Vec::new(),
        })
    }
}

impl Driver for KzIdCard {
    fn kind(&self) -> TokenKind {
        TokenKind::KzIdCard
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }

    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError> {
        self.check_pin(pin)?;
        let mut padded = pin.as_bytes().to_vec();
        padded.resize(8, b'0');
        select_mf(card)?;
        let resp = card.transmit(
            &Command::new(0x00, 0x20, 0x00, 0x02)
                .with_data(padded)
                .redacted(),
        )?;
        match resp.sw {
            0x9000 => Ok(()),
            0x6983 | 0x6984 => Err(TokenError::PinBlocked),
            sw if sw >> 8 == 0x63 => Err(TokenError::WrongPin {
                tries_left: Some(resp.sw2() & 0x0F),
            }),
            _ => Err(TokenError::WrongPin { tries_left: None }),
        }
    }

    fn keys(&mut self, card: &mut Card<'_>) -> Result<Vec<KeySlot>, TokenError> {
        let mut slots = Vec::new();
        self.public.clear();
        for pair in PAIRS {
            let mut keys = Vec::new();
            for (reference, _) in pair {
                match read_public(card, reference) {
                    Ok(key) => keys.push(key),
                    Err(e @ (TokenError::Card { .. } | TokenError::Malformed(_))) => {
                        tracing::debug!("ID card: no public key {reference:02X}: {e}");
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            if keys.len() < 2 {
                continue;
            }
            for ((reference, prefix), key) in pair.into_iter().zip(keys) {
                slots.push(KeySlot {
                    alias: format!("{prefix}{}", self.token_id),
                    id: u16::from(reference),
                    alg: if reference & 0x80 != 0 {
                        KeyAlg::Rsa
                    } else {
                        KeyAlg::Gost2015_512
                    },
                });
                self.public.push((u16::from(reference), key));
            }
        }
        Ok(slots)
    }

    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError> {
        if let Some((_, key)) = self.public.iter().find(|(id, _)| *id == slot.id) {
            return Ok(key.clone());
        }
        read_public(card, slot.id as u8)
    }

    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError> {
        select_mf(card)?;
        card.expect(&select(0x01, &[0x08, 0x01]), "select the certificates")?;
        card.expect(
            &select(0x02, &[0x01, cert_ef(slot.id as u8)]),
            "select a certificate",
        )?;
        let len = card.read_binary(0, 2)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if len == 0 {
            return Ok(None);
        }
        if len > crate::MAX_GZ_CERT {
            return Err(TokenError::Malformed(format!(
                "a certificate of {len} bytes"
            )));
        }
        cert_bytes(&card.read_binary(2, len)?).map(Some)
    }

    fn sign(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
        _alg: SigAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        let reference = slot.id as u8;
        select_mf(card)?;
        select_keys(card)?;
        let mse = |p2: u8, reference: u8, alg: u8| {
            Command::new(0x00, 0x22, 0x41, p2)
                .with_data([0x95, 0x01, 0x40, 0x84, 0x01, reference, 0x80, 0x01, alg])
        };
        if slot.alg == KeyAlg::Rsa {
            let resp = card.transmit(&mse(0xA4, reference, 0x02))?;
            if resp.sw == 0x6A80 {
                // Cards of 2020 take the reference without bit 7.
                card.expect(&mse(0xA4, reference & 0x7F, 0x02), "set the signing key")?;
            } else if !resp.is_ok() {
                return Err(TokenError::Card {
                    op: "set the signing key",
                    sw: resp.sw,
                });
            }
            // The card pads the DigestInfo itself; the signature comes big-endian.
            return card.expect(
                &Command::new(0x00, 0x88, 0x02, 0x00).with_data(digest),
                "sign",
            );
        }
        // The status of this MSE is not checked, as the PSO tells.
        card.transmit(&mse(0xB6, reference, 0x74))?;
        let sig = card.expect(
            &Command::new(0x00, 0x2A, 0x9E, 0x9A).with_data(reversed(digest)),
            "sign",
        )?;
        if sig.len() != 128 {
            return Err(TokenError::Malformed(format!(
                "a signature of {} bytes",
                sig.len()
            )));
        }
        // Unverified on hardware: the card is taken to answer r_BE ‖ s_BE.
        Ok(reverse_halves(&sig))
    }

    fn logout(&mut self, _card: &mut Card<'_>) -> Result<(), TokenError> {
        // The card has no logout command: the reset at disconnect ends the verification.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dg11_names() {
        let names = |middle: Option<&str>| {
            let mut body = vec![0x5C, 0x05, 0x5F, 0x0E, 0x5F, 0x2B, 0xA0];
            body.extend([0x5F, 0x0E, 3]);
            body.extend(b"AAA");
            let mut other = Vec::new();
            if let Some(m) = middle {
                other.extend([0x5F, 0x0F, m.len() as u8]);
                other.extend(m.as_bytes());
            }
            other.extend([0x5F, 0x0F, 2]);
            other.extend(b"BB");
            body.push(0xA0);
            body.push(other.len() as u8);
            body.extend(other);
            let mut dg = vec![0x6B, body.len() as u8];
            dg.extend(body);
            parse_dg11(&dg).unwrap()
        };
        assert_eq!(
            names(Some("CC")),
            ("AAA".to_owned(), "BB".to_owned(), Some("CC".to_owned()))
        );
        assert_eq!(names(None), ("AAA".to_owned(), "BB".to_owned(), None));
        assert!(parse_dg11(&[0x6B, 0x05, 0]).is_err());
    }
}
