//! The Gamma applet family: eToken 5110 and JaCarta. Named objects as on the eToken 72K;
//! RSA blocks and certificates in extended APDUs over T=1 (the eToken 5110 has a chunked
//! form for T=0, JaCarta none).

use super::etoken72k::{count, name_bytes, object_name, probe, serial};
use super::util::{gost_public, hex, pkcs1_type1, reverse_halves, reversed, rsa_public};
use super::{Driver, KeySlot, wrong_card};
use crate::apdu::Command;
use crate::backend::Protocol;
use crate::card::Card;
use crate::error::TokenError;
use crate::gzip::cert_bytes;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// Checked on an emulated card only.
pub const HARDWARE_VERIFIED: bool = false;

/// Size of the RSA block the driver pads: RSA-2048 only.
const RSA_BLOCK: usize = 256;

/// Most certificate bytes read in one T=0 command.
const T0_CHUNK: usize = 0xE0;

/// The applet of the eToken 5110: `A0 00 "gammatechg" 00`.
const AID_5110: &[u8] = b"\xA0\x00gammatechg\x00";
/// The applet of JaCarta: `A0 00 "gammatech" 00`.
const AID_JACARTA: &[u8] = b"\xA0\x00gammatech\x00";

pub(super) struct Gamma {
    kind: TokenKind,
    token_id: String,
}

impl Gamma {
    pub(super) fn open(kind: TokenKind, card: &mut Card<'_>) -> Result<Gamma, TokenError> {
        let aid = match kind {
            TokenKind::EToken5110 => AID_5110,
            _ => AID_JACARTA,
        };
        card.expect(
            &Command::new(0x00, 0xA4, 0x04, 0x00).with_data(aid),
            "select the applet",
        )
        .map_err(wrong_card)?;
        card.expect(&Command::new(0x80, 0x15, 0x20, 0x00), "token information")
            .map_err(wrong_card)?;
        let info = card
            .expect(
                &Command::new(0x80, 0x15, 0x21, 0x00).with_le(0x64),
                "token information",
            )
            .map_err(wrong_card)?;
        Ok(Gamma {
            kind,
            token_id: serial(&info)?,
        })
    }

    fn is_5110(&self) -> bool {
        self.kind == TokenKind::EToken5110
    }

    fn key_alg(&self, card: &mut Card<'_>, name: &[u8]) -> Result<Option<KeyAlg>, TokenError> {
        if probe(card, 0x24, name, 0x00)? {
            if !self.is_5110() {
                return Ok(Some(KeyAlg::Gost2004));
            }
            let mut data = name.to_vec();
            data.extend([0x00, 0x00]);
            let ty = card.expect(
                &Command::new(0x80, 0x11, 0x22, 0x00)
                    .with_data(data)
                    .with_le(1),
                "read the key type",
            )?;
            return Ok(match ty.first() {
                Some(0x01) => Some(KeyAlg::Gost2004),
                Some(0x0C) => Some(KeyAlg::Gost2015_512),
                _ => None,
            });
        }
        Ok(probe(card, 0x24, name, 0x03)?.then_some(KeyAlg::Rsa))
    }
}

impl Driver for Gamma {
    fn kind(&self) -> TokenKind {
        self.kind
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }

    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError> {
        self.check_pin(pin)?;
        let resp = card.transmit(
            &Command::new(0x80, 0x10, 0x21, 0x00)
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
        let count_cmd = Command::new(0x80, 0x12, 0x22, 0x00);
        let count_cmd = if self.is_5110() {
            count_cmd.with_le(256)
        } else {
            count_cmd
        };
        let n = count(&card.expect(&count_cmd, "count the keys")?)?;
        let mut slots = Vec::new();
        for i in 0..n {
            let name_cmd = Command::new(0x80, 0x12, 0x21, 0x00).with_data(i.to_be_bytes());
            let name_cmd = if self.is_5110() {
                name_cmd.with_le(0x32)
            } else {
                name_cmd
            };
            let data = card.expect(&name_cmd, "read a key name")?;
            let probe_slot = KeySlot {
                alias: hex(name_bytes(&data)),
                id: i,
                alg: KeyAlg::Rsa,
            };
            let name = object_name(&probe_slot)?;
            let Some(alg) = self.key_alg(card, &name)? else {
                tracing::warn!(
                    "{}: key {} of an unsupported type",
                    self.kind.storage_name(),
                    probe_slot.alias
                );
                continue;
            };
            if alg == KeyAlg::Rsa && !self.is_5110() && card.protocol() == Protocol::T0 {
                tracing::error!(
                    "JaCarta: RSA key {} needs extended APDUs, which T=0 cannot carry",
                    probe_slot.alias
                );
                continue;
            }
            slots.push(KeySlot { alg, ..probe_slot });
        }
        Ok(slots)
    }

    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError> {
        let name = object_name(slot)?;
        if slot.alg != KeyAlg::Rsa {
            let cmd = Command::new(0x80, 0x11, 0x21, 0x00).with_data(name);
            let cmd = if self.is_5110() {
                cmd.with_le(0xFF)
            } else {
                cmd
            };
            let xy = card.expect(&cmd, "read public key")?;
            return gost_public(slot.alg, &reverse_halves(&xy));
        }
        let cmd = if card.protocol() == Protocol::T0 {
            Command::new(0x80, 0x12, 0x25, 0x05).with_data(name)
        } else if self.is_5110() {
            Command::new(0x80, 0x12, 0x25, 0x00)
                .with_data(name)
                .with_le(260)
        } else {
            Command::new(0x80, 0x12, 0x25, 0x00).with_data(name)
        };
        let data = card.expect(&cmd, "read public key")?;
        match data.get(3..3 + RSA_BLOCK) {
            Some(modulus) => rsa_public(modulus),
            None => Err(TokenError::Malformed(format!(
                "an RSA public key of {} bytes; only RSA-2048 is supported",
                data.len()
            ))),
        }
    }

    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError> {
        let name = object_name(slot)?;
        let raw = if self.is_5110() && card.protocol() == Protocol::T0 {
            let mut data = name.clone();
            data.extend([0x00, 0x00]);
            let resp = card.transmit(&Command::new(0x80, 0x12, 0x28, 0x05).with_data(data))?;
            if !resp.is_ok() {
                return Ok(None);
            }
            let len = usize::from(count(&resp.data)?);
            if len > crate::MAX_GZ_CERT {
                return Err(TokenError::Malformed(format!(
                    "a certificate of {len} bytes"
                )));
            }
            let mut raw = Vec::with_capacity(len);
            while raw.len() < len {
                let n = (len - raw.len()).min(T0_CHUNK);
                let mut data = name.clone();
                data.extend((raw.len() as u16).to_be_bytes());
                data.push(n as u8);
                let chunk = card.expect(
                    &Command::new(0x80, 0x12, 0x28, 0x05).with_data(data),
                    "read the certificate",
                )?;
                if chunk.is_empty() || chunk.len() > n {
                    return Err(TokenError::Malformed(
                        "a broken certificate chunk".to_owned(),
                    ));
                }
                raw.extend(chunk);
            }
            raw
        } else {
            let cmd = Command::new(0x80, 0x12, 0x28, 0x00).with_data(name);
            let cmd = if self.is_5110() {
                cmd.with_le(4096)
            } else {
                cmd
            };
            let resp = card.transmit(&cmd)?;
            if !resp.is_ok() {
                return Ok(None);
            }
            resp.data
        };
        if raw.is_empty() {
            return Ok(None);
        }
        // What follows the compressed certificate (a status word some cards repeat) is
        // ignored.
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
            let cmd = Command::new(0x80, 0x14, 0x20, 0x00).with_data(data);
            let cmd = if self.is_5110() {
                cmd.with_le(0xFF)
            } else {
                cmd
            };
            let sig = card.expect(&cmd, "sign")?;
            if sig.len() != 2 * digest.len() {
                return Err(TokenError::Malformed(format!(
                    "a signature of {} bytes",
                    sig.len()
                )));
            }
            return Ok(reverse_halves(&sig));
        }
        let block = pkcs1_type1(digest, RSA_BLOCK)?;
        let mut data = name;
        data.extend([0x01, 0x00]);
        if card.protocol() == Protocol::T0 {
            // The block goes in two pieces `<len> <offset> <bytes>`; the signing command
            // names the key only.
            for (off, piece) in [(0, &block[..224]), (224, &block[224..])] {
                let mut load = (piece.len() as u16).to_be_bytes().to_vec();
                load.extend((off as u16).to_be_bytes());
                load.extend(piece);
                card.expect(
                    &Command::new(0x80, 0x14, 0x24, 0x00).with_data(load),
                    "sign",
                )?;
            }
            return card.expect(
                &Command::new(0x80, 0x14, 0x23, 0x24).with_data(data),
                "sign",
            );
        }
        data.extend(&block);
        let cmd = Command::new(0x80, 0x14, 0x23, 0x24).with_data(data);
        let cmd = if self.is_5110() {
            cmd.with_le(258)
        } else {
            cmd
        };
        card.expect(&cmd, "sign")
    }

    fn logout(&mut self, _card: &mut Card<'_>) -> Result<(), TokenError> {
        // No logout command: the reset at disconnect ends the verification.
        Ok(())
    }
}
