//! An emulated Kaztoken: the map file and the key files the driver reads, the PIN, the
//! public keys (readable without the PIN), and signing.

use super::applet::{Apdu, Applet, Reply, ok, sw};
use super::soft::{self, PinCheck, PinState};
use super::{CardSpec, EmuKey};
use oncl_pki::key::KeyAlg;

const MAP: [u8; 6] = [0x10, 0x00, 0x10, 0x10, 0x10, 0x10];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    None,
    MapDir,
    Map,
    PrivateKey(u8),
    Certificate(u8),
}

pub(crate) struct Kaztoken {
    spec: CardSpec,
    pin: PinState,
    selected: Selected,
    /// Key reference set by MSE, with its mode (`91` GOST, `95` RSA).
    key: Option<(u8, u8)>,
    /// RSA command chain so far.
    chain: Vec<u8>,
    map: Vec<u8>,
    certs: Vec<Vec<u8>>,
}

fn key_type(alg: KeyAlg) -> u8 {
    match alg {
        KeyAlg::Gost2004 => 0x03,
        KeyAlg::Rsa => 0x23,
        KeyAlg::Gost2015_512 => 0x43,
    }
}

fn fcp(size: usize, fid: [u8; 2], key_type: Option<u8>) -> Vec<u8> {
    let mut body = vec![0x80, 0x02];
    body.extend((size as u16).to_be_bytes());
    body.extend([0x82, 0x01, 0x01, 0x83, 0x02, fid[0], fid[1]]);
    if let Some(t) = key_type {
        body.extend([0x85, 0x06, t, 0x00, 0x00, 0xFF, 0x00, 0x00]);
    }
    let mut out = vec![0x62, body.len() as u8];
    out.extend(body);
    out
}

impl Kaztoken {
    pub(crate) fn new(spec: CardSpec) -> Kaztoken {
        let mut map = Vec::new();
        if !spec.keys.is_empty() {
            map.extend([0x01, 0x00, 0x00, 0x10]);
            for (i, key) in spec.keys.iter().enumerate() {
                map.push(i as u8 + 1);
                map.extend(key.entry.alias.as_bytes());
                map.push(0);
            }
        }
        let certs = spec
            .keys
            .iter()
            .map(|k| {
                let der = der::Encode::to_der(&k.entry.cert).expect("a certificate encodes");
                if spec.raw_certificates {
                    der
                } else {
                    soft::gzip(&der)
                }
            })
            .collect();
        Kaztoken {
            pin: PinState::new(&spec.pin, spec.tries, spec.max_tries),
            spec,
            selected: Selected::None,
            key: None,
            chain: Vec::new(),
            map,
            certs,
        }
    }

    fn key(&self, id: u8) -> Option<&EmuKey> {
        self.spec.keys.get(usize::from(id).checked_sub(1)?)
    }

    fn select_path(&mut self, path: &[u8]) -> Result<Vec<u8>, u16> {
        match path {
            _ if path == MAP && !self.map.is_empty() => {
                self.selected = Selected::MapDir;
                Ok(Vec::new())
            }
            [0x10, 0x00, 0x10, 0x00, 0x60, dir @ (0x02 | 0x04), 0x00, id] => {
                let alg = self.key(*id).ok_or(0x6A82u16)?.entry.key.alg();
                if *dir == 0x02 {
                    self.selected = Selected::PrivateKey(*id);
                    Ok(fcp(64, [0, *id], Some(key_type(alg))))
                } else {
                    self.selected = Selected::Certificate(*id);
                    Ok(fcp(self.certs[usize::from(*id) - 1].len(), [0, *id], None))
                }
            }
            _ => {
                self.selected = Selected::None;
                Err(0x6A82)
            }
        }
    }

    fn verify(&mut self, pin: &[u8]) -> Reply {
        if pin.is_empty() {
            return if self.pin.is_verified() {
                sw(0x9000)
            } else if self.pin.is_blocked() {
                sw(0x6983)
            } else {
                sw(0x63C0 | u16::from(self.pin.tries()))
            };
        }
        match self.pin.verify(pin) {
            PinCheck::Ok => sw(0x9000),
            PinCheck::Wrong(n) => sw(0x63C0 | u16::from(n)),
            PinCheck::Blocked => sw(0x6983),
        }
    }

    fn public_key(&self, id: u8) -> Reply {
        let Some(key) = self.key(id) else {
            return sw(0x6A88);
        };
        match key.entry.key.alg() {
            KeyAlg::Rsa => {
                let mut modulus = soft::rsa_modulus_be(&key.entry);
                modulus.reverse();
                ok(modulus)
            }
            _ => ok(soft::gost_point_le(&key.entry)),
        }
    }

    fn sign(&mut self, apdu: &Apdu) -> Reply {
        if !self.pin.is_verified() {
            return sw(0x6982);
        }
        let Some((id, mode)) = self.key else {
            return sw(0x6985);
        };
        let Some(key) = self.key(id).cloned() else {
            return sw(0x6A88);
        };
        let rsa = key.entry.key.alg() == KeyAlg::Rsa;
        if (mode == 0x95) != rsa {
            return sw(0x6A80);
        }
        if !rsa {
            if apdu.cla != 0x00 {
                return sw(0x6884);
            }
            let mut sig = soft::gost_sign(&key.entry, &apdu.data, self.spec.fixed_k.as_deref());
            if self.spec.swap_signature_halves {
                soft::swap_halves(&mut sig);
            }
            return ok(sig);
        }
        self.chain.extend(&apdu.data);
        if apdu.cla == 0x10 {
            return sw(0x9000);
        }
        // The chain is the PKCS#1 block little-endian.
        let mut block = std::mem::take(&mut self.chain);
        block.reverse();
        match soft::rsa_sign_block(&key.entry, &block) {
            Ok(mut sig) => {
                sig.reverse();
                ok(sig)
            }
            Err(status) => sw(status),
        }
    }
}

impl Applet for Kaztoken {
    fn handle(&mut self, apdu: &Apdu) -> Reply {
        if apdu.cla == 0x10 && apdu.ins != 0x2A {
            return sw(0x6884);
        }
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x00, 0xCA, 0x01, 0x81) => {
                let mut data = vec![0x01, 0x81, 0x00, 0x08];
                data.extend(self.spec.serial);
                ok(data)
            }
            (0x80, 0x40, 0x00, 0x00) => {
                self.pin.reset();
                self.key = None;
                sw(0x9000)
            }
            (0x00, 0x20, 0x00, 0x02) => self.verify(&apdu.data.clone()),
            (0x00, 0xA4, 0x08, 0x04) => match self.select_path(&apdu.data) {
                Ok(fcp) if apdu.le.is_some() => ok(fcp),
                Ok(_) => sw(0x9000),
                Err(status) => sw(status),
            },
            (0x00, 0xA4, 0x00, 0x04) => {
                if self.selected == Selected::MapDir && apdu.data == [0x10, 0x10] {
                    self.selected = Selected::Map;
                    ok(fcp(self.map.len(), [0x10, 0x10], None))
                } else {
                    sw(0x6A82)
                }
            }
            (0x00, 0xB0, hi, lo) => {
                let file = match self.selected {
                    Selected::Map => &self.map,
                    Selected::Certificate(id) => &self.certs[usize::from(id) - 1],
                    _ => return sw(0x6986),
                };
                let offset = usize::from(u16::from_be_bytes([hi, lo]));
                let len = apdu.le.map_or(0, |le| le as usize);
                match file.get(offset..) {
                    Some(rest) if !rest.is_empty() => ok(rest[..len.min(rest.len())].to_vec()),
                    _ => sw(0x6B00),
                }
            }
            (0x00, 0x46, 0x81, id) => self.public_key(id),
            (0x00, 0x22, 0x41, 0xB6) => match apdu.data.as_slice() {
                [mode @ (0x91 | 0x95), 0x01, 0x40, 0x84, 0x01, id] if self.key(*id).is_some() => {
                    self.key = Some((*id, *mode));
                    self.chain.clear();
                    sw(0x9000)
                }
                _ => sw(0x6A80),
            },
            (0x00 | 0x10, 0x2A, 0x9E, 0x9A) => self.sign(apdu),
            _ => sw(0x6D00),
        }
    }

    fn reset(&mut self) {
        self.pin.reset();
        self.selected = Selected::None;
        self.key = None;
        self.chain.clear();
    }
}
