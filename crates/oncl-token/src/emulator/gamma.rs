//! An emulated eToken 5110 or JaCarta: the Gamma applet of named objects, the PIN without a
//! count of tries, RSA blocks in one extended command (T=1) or in pieces (eToken 5110 over
//! T=0).

use super::CardSpec;
use super::applet::{Apdu, Applet, Reply, ok, sw};
use super::etoken72k::{Objects, token_info};
use super::soft::{self, PinCheck, PinState};
use crate::backend::Protocol;
use crate::kind::TokenKind;
use oncl_pki::key::KeyAlg;

pub(crate) struct Gamma {
    spec: CardSpec,
    aid: &'static [u8],
    pin: PinState,
    selected: bool,
    objects: Objects,
    /// The RSA block loaded in pieces.
    block: Vec<u8>,
}

fn key_type(alg: KeyAlg) -> u8 {
    match alg {
        KeyAlg::Gost2004 => 0x01,
        KeyAlg::Gost2015_512 => 0x0C,
        KeyAlg::Rsa => 0x00,
    }
}

impl Gamma {
    pub(crate) fn new(spec: CardSpec) -> Gamma {
        let is_5110 = spec.kind == TokenKind::EToken5110;
        Gamma {
            aid: if is_5110 {
                b"\xA0\x00gammatechg\x00"
            } else {
                b"\xA0\x00gammatech\x00"
            },
            pin: PinState::new(&spec.pin, spec.tries, spec.max_tries),
            // The eToken 5110 answers its certificate object with a status word after the
            // compressed certificate, as some of these tokens do.
            objects: Objects::new(&spec, |der| {
                let mut gz = soft::gzip(&der);
                if is_5110 {
                    gz.extend([0x90, 0x00]);
                }
                gz
            }),
            spec,
            selected: false,
            block: vec![0; 256],
        }
    }

    fn is_5110(&self) -> bool {
        self.spec.kind == TokenKind::EToken5110
    }

    fn t0(&self) -> bool {
        self.spec.protocol == Protocol::T0
    }

    fn supports(&self, alg: KeyAlg) -> bool {
        self.is_5110() || alg != KeyAlg::Gost2015_512
    }

    fn rsa_public(&self, apdu: &Apdu) -> Reply {
        if apdu.p2 != if self.t0() { 0x05 } else { 0x00 } {
            return sw(0x6A86);
        }
        let Some((i, [])) = self.objects.find(&apdu.data) else {
            return sw(0x6A88);
        };
        if self.objects.alg(i) != KeyAlg::Rsa {
            return sw(0x6A80);
        }
        let mut out = vec![0x81, 0x01, 0x00];
        out.extend(soft::rsa_modulus_be(&self.objects.key(i).entry));
        ok(out)
    }

    fn gost_public(&self, data: &[u8]) -> Reply {
        let Some((i, [])) = self.objects.find(data) else {
            return sw(0x6A88);
        };
        let alg = self.objects.alg(i);
        if alg == KeyAlg::Rsa || !self.supports(alg) {
            return sw(0x6A80);
        }
        let xy = soft::gost_point_le(&self.objects.key(i).entry);
        ok(crate::drivers::util::reverse_halves(&xy))
    }

    fn sign_gost(&self, data: &[u8]) -> Reply {
        let Some((i, hash)) = self.objects.find(data) else {
            return sw(0x6A88);
        };
        let alg = self.objects.alg(i);
        let len = if alg == KeyAlg::Gost2004 { 32 } else { 64 };
        if alg == KeyAlg::Rsa || !self.supports(alg) || hash.len() != len {
            return sw(0x6A80);
        }
        let hash: Vec<u8> = hash.iter().rev().copied().collect();
        let mut sig = soft::gost_sign(
            &self.objects.key(i).entry,
            &hash,
            self.spec.fixed_k.as_deref(),
        );
        if self.spec.swap_signature_halves {
            soft::swap_halves(&mut sig);
        }
        ok(crate::drivers::util::reverse_halves(&sig))
    }

    fn sign_rsa(&mut self, data: &[u8]) -> Reply {
        let Some((i, rest)) = self.objects.find(data) else {
            return sw(0x6A88);
        };
        let block = match rest {
            [0x01, 0x00] if self.is_5110() && self.t0() => {
                std::mem::replace(&mut self.block, vec![0; 256])
            }
            [0x01, 0x00, block @ ..] if block.len() == 256 && !self.t0() => block.to_vec(),
            _ => return sw(0x6A80),
        };
        if self.objects.alg(i) != KeyAlg::Rsa {
            return sw(0x6A80);
        }
        match soft::rsa_sign_block(&self.objects.key(i).entry, &block) {
            Ok(sig) => ok(sig),
            Err(status) => sw(status),
        }
    }

    fn load_block(&mut self, data: &[u8]) -> Reply {
        let [lh, ll, oh, ol, piece @ ..] = data else {
            return sw(0x6700);
        };
        let len = usize::from(u16::from_be_bytes([*lh, *ll]));
        let off = usize::from(u16::from_be_bytes([*oh, *ol]));
        if !self.is_5110() || !self.t0() || piece.len() != len || off + len > 256 {
            return sw(0x6A80);
        }
        self.block[off..off + len].copy_from_slice(piece);
        sw(0x9000)
    }

    fn certificate(&self, apdu: &Apdu) -> Reply {
        let Some((i, rest)) = self.objects.find(&apdu.data) else {
            return sw(0x6A88);
        };
        let stored = &self.objects.keys[i].2;
        match (apdu.p2, rest) {
            (0x00, []) if !self.t0() || !self.is_5110() => {
                let n = apdu.le.map_or(stored.len(), |le| le as usize);
                ok(stored[..n.min(stored.len())].to_vec())
            }
            (0x05, [0x00, 0x00]) if self.t0() && self.is_5110() => {
                ok((stored.len() as u16).to_be_bytes().to_vec())
            }
            (0x05, [oh, ol, n]) if self.t0() && self.is_5110() => {
                let off = usize::from(u16::from_be_bytes([*oh, *ol]));
                match stored.get(off..) {
                    Some(rest) if !rest.is_empty() => {
                        ok(rest[..usize::from(*n).min(rest.len())].to_vec())
                    }
                    _ => sw(0x6B00),
                }
            }
            _ => sw(0x6A86),
        }
    }
}

impl Applet for Gamma {
    fn handle(&mut self, apdu: &Apdu) -> Reply {
        if (apdu.cla, apdu.ins, apdu.p1, apdu.p2) == (0x00, 0xA4, 0x04, 0x00) {
            self.selected = apdu.data == self.aid;
            return sw(if self.selected { 0x9000 } else { 0x6A82 });
        }
        if !self.selected {
            return sw(0x6D00);
        }
        let verified = self.pin.is_verified();
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x80, 0x15, 0x20, 0x00) => sw(0x9000),
            (0x80, 0x15, 0x21, 0x00) => ok(token_info(&self.spec)),
            (0x80, 0x10, 0x21, 0x00) => match self.pin.verify(&apdu.data) {
                PinCheck::Ok => sw(0x9000),
                PinCheck::Wrong(_) => sw(0x6982),
                PinCheck::Blocked => sw(0x6983),
            },
            (0x80, 0x12, 0x22, 0x00) => {
                if self.is_5110() != apdu.le.is_some() {
                    return sw(0x6700);
                }
                ok((self.objects.keys.len() as u16).to_be_bytes().to_vec())
            }
            (0x80, 0x12, 0x21, 0x00) => match apdu.data.as_slice() {
                [hi, lo]
                    if usize::from(u16::from_be_bytes([*hi, *lo])) < self.objects.keys.len() =>
                {
                    ok(self
                        .objects
                        .name(usize::from(u16::from_be_bytes([*hi, *lo]))))
                }
                _ => sw(0x6A88),
            },
            (0x80, 0x12, 0x24, 0x00) => match self.objects.find(&apdu.data) {
                Some((i, [0x00, 0x00]))
                    if self.objects.alg(i) != KeyAlg::Rsa && self.supports(self.objects.alg(i)) =>
                {
                    sw(0x9000)
                }
                Some((i, [0x00, 0x03])) if self.objects.alg(i) == KeyAlg::Rsa => sw(0x9000),
                Some(_) => sw(0x6A80),
                None => sw(0x6A88),
            },
            (0x80, 0x11, 0x22, 0x00) if self.is_5110() => match self.objects.find(&apdu.data) {
                Some((i, [0x00, 0x00])) => ok(vec![key_type(self.objects.alg(i))]),
                _ => sw(0x6A88),
            },
            (0x80, 0x11, 0x21, 0x00) => self.gost_public(&apdu.data),
            (0x80, 0x12, 0x25, _) => self.rsa_public(apdu),
            (0x80, 0x12, 0x28, _) => self.certificate(apdu),
            (0x80, 0x14, 0x20, 0x00) if verified => self.sign_gost(&apdu.data),
            (0x80, 0x14, 0x24, 0x00) if verified => self.load_block(&apdu.data.clone()),
            (0x80, 0x14, 0x23, 0x24) if verified => self.sign_rsa(&apdu.data.clone()),
            (0x80, 0x14, _, _) => sw(0x6982),
            _ => sw(0x6D00),
        }
    }

    fn reset(&mut self) {
        self.pin.reset();
        self.selected = false;
        self.block = vec![0; 256];
    }
}
