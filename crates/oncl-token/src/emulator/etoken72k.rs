//! An emulated eToken PRO 72K: the applet of named objects (named after the keys' aliases),
//! the PIN without a count of tries, GOST signatures in two halves, RSA blocks through a
//! buffer of 32-byte pieces.

use super::applet::{Apdu, Applet, Reply, ok, sw};
use super::soft::{self, PinCheck, PinState};
use super::{CardSpec, EmuKey};
use oncl_pki::key::KeyAlg;

const AID: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00];

/// The keys of a card of named objects: wire name `00 <len> <name>`, key, stored
/// certificate.
pub(super) struct Objects {
    pub keys: Vec<(Vec<u8>, EmuKey, Vec<u8>)>,
}

impl Objects {
    pub(super) fn new(spec: &CardSpec, stored: impl Fn(Vec<u8>) -> Vec<u8>) -> Objects {
        Objects {
            keys: spec
                .keys
                .iter()
                .map(|k| {
                    let name = k.entry.alias.as_bytes();
                    let mut wire = vec![0x00, name.len() as u8];
                    wire.extend(name);
                    let der = der::Encode::to_der(&k.entry.cert).expect("a certificate encodes");
                    (wire, k.clone(), stored(der))
                })
                .collect(),
        }
    }

    /// The key whose wire name starts `data`, and what follows the name.
    pub(super) fn find<'a>(&self, data: &'a [u8]) -> Option<(usize, &'a [u8])> {
        self.keys
            .iter()
            .position(|(name, _, _)| data.starts_with(name))
            .map(|i| (i, &data[self.keys[i].0.len()..]))
    }

    pub(super) fn name(&self, i: usize) -> Vec<u8> {
        let mut name = self.keys[i].0[2..].to_vec();
        name.push(0);
        name
    }

    pub(super) fn key(&self, i: usize) -> &EmuKey {
        &self.keys[i].1
    }

    pub(super) fn alg(&self, i: usize) -> KeyAlg {
        self.keys[i].1.entry.key.alg()
    }
}

/// Token information with the serial at bytes 9..17.
pub(super) fn token_info(spec: &CardSpec) -> Vec<u8> {
    let mut info = vec![0u8; 100];
    info[..9].copy_from_slice(b"OpenNCALa");
    info[9..17].copy_from_slice(&spec.serial);
    info
}

pub(crate) struct EToken72K {
    spec: CardSpec,
    pin: PinState,
    selected: bool,
    objects: Objects,
    /// The second half of the last GOST signature.
    second_half: Vec<u8>,
    /// The RSA block being loaded, and the last RSA signature.
    block: Vec<u8>,
    signature: Vec<u8>,
    /// The certificate object selected.
    cert: Option<usize>,
}

impl EToken72K {
    pub(crate) fn new(spec: CardSpec) -> EToken72K {
        EToken72K {
            pin: PinState::new(&spec.pin, spec.tries, spec.max_tries),
            objects: Objects::new(&spec, |der| soft::gzip(&der)),
            spec,
            selected: false,
            second_half: Vec::new(),
            block: vec![0; 256],
            signature: Vec::new(),
            cert: None,
        }
    }

    fn sign_gost(&mut self, data: &[u8]) -> Reply {
        let Some((i, hash)) = self.objects.find(data) else {
            return sw(0x6A88);
        };
        if self.objects.alg(i) != KeyAlg::Gost2004 || hash.len() != 32 {
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
        let r: Vec<u8> = sig[..32].iter().rev().copied().collect();
        self.second_half = sig[32..].iter().rev().copied().collect();
        ok(r)
    }

    fn sign_rsa(&mut self, data: &[u8]) -> Reply {
        let Some((i, [])) = data
            .strip_prefix(&[0x01, 0x00])
            .and_then(|d| self.objects.find(d))
        else {
            return sw(0x6A80);
        };
        if self.objects.alg(i) != KeyAlg::Rsa {
            return sw(0x6A80);
        }
        match soft::rsa_sign_block(&self.objects.key(i).entry, &self.block) {
            Ok(sig) => {
                self.signature = sig;
                sw(0x9000)
            }
            Err(status) => sw(status),
        }
    }

    fn public_key(&self, apdu: &Apdu) -> Reply {
        match (apdu.ins, apdu.p1, apdu.p2) {
            (0x11, p1 @ (0x21 | 0x24), 0x00) => {
                let Some((i, [])) = self.objects.find(&apdu.data) else {
                    return sw(0x6A88);
                };
                if self.objects.alg(i) != KeyAlg::Gost2004 {
                    return sw(0x6A80);
                }
                let xy = soft::gost_point_le(&self.objects.key(i).entry);
                let half = if p1 == 0x21 { &xy[..32] } else { &xy[32..] };
                ok(half.iter().rev().copied().collect())
            }
            (0x12, 0x47, p2 @ (0x00 | 0x01)) => {
                let Some((off, name)) = apdu.data.split_at_checked(2) else {
                    return sw(0x6700);
                };
                let Some((i, [])) = self.objects.find(name) else {
                    return sw(0x6A88);
                };
                if self.objects.alg(i) != KeyAlg::Rsa {
                    return sw(0x6A80);
                }
                let modulus = soft::rsa_modulus_be(&self.objects.key(i).entry);
                if p2 == 0x00 {
                    return ok(((modulus.len() * 8) as u16).to_be_bytes().to_vec());
                }
                let off = usize::from(u16::from_be_bytes([off[0], off[1]]));
                match modulus.get(off..off + 32) {
                    Some(block) => ok(block.to_vec()),
                    None => sw(0x6B00),
                }
            }
            _ => sw(0x6D00),
        }
    }
}

impl Applet for EToken72K {
    fn handle(&mut self, apdu: &Apdu) -> Reply {
        if (apdu.cla, apdu.ins, apdu.p1, apdu.p2) == (0x00, 0xA4, 0x04, 0x00) {
            self.selected = apdu.data == AID;
            return sw(if self.selected { 0x9000 } else { 0x6A82 });
        }
        if !self.selected {
            return sw(0x6D00);
        }
        let verified = self.pin.is_verified();
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x80, 0x15, 0x20, 0x00) => sw(0x9000),
            (0x80, 0x15, 0x10, 0x00) => ok(token_info(&self.spec)),
            (0x80, 0x10, 0x20, 0x00) => match self.pin.verify(&apdu.data) {
                PinCheck::Ok => sw(0x9000),
                PinCheck::Wrong(_) => sw(0x6982),
                PinCheck::Blocked => sw(0x6983),
            },
            (0x80, 0x12, 0x22, 0x00) => ok((self.objects.keys.len() as u16).to_be_bytes().to_vec()),
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
            (0x80, 0x12, 0x44, 0x00) => match self.objects.find(&apdu.data) {
                Some((i, [0x00, 0x00])) if self.objects.alg(i) == KeyAlg::Gost2004 => sw(0x9000),
                Some((i, [0x00, 0x03])) if self.objects.alg(i) == KeyAlg::Rsa => sw(0x9000),
                Some(_) => sw(0x6A80),
                None => sw(0x6A88),
            },
            (0x80, 0x11, 0x21 | 0x24, 0x00) | (0x80, 0x12, 0x47, _) => self.public_key(apdu),
            (0x80, 0x12, 0x43, 0x00) => match self.objects.find(&apdu.data) {
                Some((i, [])) => {
                    self.cert = Some(i);
                    sw(0x9000)
                }
                _ => sw(0x6A82),
            },
            (0x80, 0x12, 0x41, 0x00) => {
                let Some(stored) = self.cert.map(|i| &self.objects.keys[i].2) else {
                    return sw(0x6985);
                };
                match apdu.data.as_slice() {
                    [0x00, 0x00] => ok((stored.len() as u16).to_be_bytes().to_vec()),
                    [nh, nl, oh, ol] => {
                        let n = usize::from(u16::from_be_bytes([*nh, *nl]));
                        let off = usize::from(u16::from_be_bytes([*oh, *ol]));
                        match stored.get(off..) {
                            Some(rest) if !rest.is_empty() => {
                                ok(rest[..n.min(rest.len())].to_vec())
                            }
                            _ => sw(0x6B00),
                        }
                    }
                    _ => sw(0x6700),
                }
            }
            (0x80, 0x14, 0x10, 0x00) if verified => self.sign_gost(&apdu.data.clone()),
            (0x80, 0x11, 0x25, 0x00) if verified => {
                if self.second_half.is_empty() {
                    sw(0x6985)
                } else {
                    ok(std::mem::take(&mut self.second_half))
                }
            }
            (0x80, 0x12, 0x49, 0x00) if verified => match apdu.data.as_slice() {
                [0x00, off, piece @ ..] if piece.len() == 32 && usize::from(*off) + 32 <= 256 => {
                    let off = usize::from(*off);
                    self.block[off..off + 32].copy_from_slice(piece);
                    sw(0x9000)
                }
                _ => sw(0x6A80),
            },
            (0x80, 0x14, 0x52, 0x77) if verified => self.sign_rsa(&apdu.data.clone()),
            (0x80, 0x12, 0x48, 0x00) if verified => match apdu.data.as_slice() {
                [hi, lo] => {
                    let off = usize::from(u16::from_be_bytes([*hi, *lo]));
                    match self.signature.get(off..off + 32) {
                        Some(piece) => ok(piece.to_vec()),
                        None => sw(0x6985),
                    }
                }
                _ => sw(0x6700),
            },
            (0x80, 0x14 | 0x11 | 0x12, _, _) => sw(0x6982),
            _ => sw(0x6D00),
        }
    }

    fn reset(&mut self) {
        self.pin.reset();
        self.selected = false;
        self.second_half.clear();
        self.block = vec![0; 256];
        self.signature.clear();
        self.cert = None;
    }
}
