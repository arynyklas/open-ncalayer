//! An emulated ID card: the MF with the key DF `0101`, the certificate DF `0801`, the IIN EF
//! `0301` and the travel document application with data group 11; the PIN of 4 characters
//! padded with `0` to 8; T=0 with GET RESPONSE by default.

use super::applet::{Apdu, Applet, Reply, ok, sw};
use super::soft::{self, PinCheck, PinState};
use super::{CardSpec, EmuKey};
use crate::drivers::util::{reverse_halves, reversed};
use oncl_pki::key::KeyAlg;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    Mf,
    Keys,
    Certs,
    Cert(u8),
    Iin,
    TravelDocument,
}

pub(crate) struct KzIdCard {
    spec: CardSpec,
    pin: PinState,
    selected: Selected,
    /// Keys by reference.
    keys: Vec<(u8, EmuKey)>,
    /// EF `0101` and `0102`: length and gzip of a certificate.
    certs: [Vec<u8>; 2],
    dg11: Vec<u8>,
    /// Key set by MSE.
    key: Option<u8>,
}

fn cert_file(key: Option<&EmuKey>) -> Vec<u8> {
    let Some(key) = key else {
        return vec![0, 0];
    };
    let gz = soft::gzip(&der::Encode::to_der(&key.entry.cert).expect("a certificate encodes"));
    let mut out = (gz.len() as u16).to_be_bytes().to_vec();
    out.extend(gz);
    out
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.push(value.len() as u8);
    out.extend(value);
    out
}

impl KzIdCard {
    pub(crate) fn new(spec: CardSpec) -> KzIdCard {
        let gost: Vec<&EmuKey> = spec
            .keys
            .iter()
            .filter(|k| k.entry.key.alg() == KeyAlg::Gost2015_512)
            .collect();
        let rsa: Vec<&EmuKey> = spec
            .keys
            .iter()
            .filter(|k| k.entry.key.alg() == KeyAlg::Rsa)
            .collect();
        let mut keys = Vec::new();
        for (reference, key) in [(0x01, gost.first()), (0x02, gost.get(1))] {
            if let Some(key) = key {
                keys.push((reference, (*key).clone()));
            }
        }
        // Cards hold both keys of a pair; one RSA key fills both.
        for (reference, key) in [(0x87, rsa.first()), (0x88, rsa.get(1).or(rsa.first()))] {
            if let Some(key) = key {
                keys.push((reference, (*key).clone()));
            }
        }
        let first = if spec.id_card_rsa_cert_first {
            rsa.first()
        } else {
            gost.first()
        };
        let certs = [cert_file(first.copied()), cert_file(gost.get(1).copied())];
        let dg11 = spec.id_card.as_ref().map_or_else(Vec::new, |info| {
            let mut other = tlv(&[0x02], &[0x02]);
            other.extend(tlv(
                &[0x5F, 0x0F],
                info.middle_name.as_deref().unwrap_or_default().as_bytes(),
            ));
            other.extend(tlv(&[0x5F, 0x0F], info.first_name.as_bytes()));
            let mut body = tlv(&[0x5C], &[0x5F, 0x0E, 0x5F, 0x2B, 0xA0]);
            body.extend(tlv(&[0x5F, 0x0E], info.last_name.as_bytes()));
            body.extend(tlv(&[0x5F, 0x2B], b"19900101"));
            body.extend(tlv(&[0xA0], &other));
            tlv(&[0x6B], &body)
        });
        KzIdCard {
            pin: PinState::new(&format!("{:0<8}", spec.pin), spec.tries, spec.max_tries),
            spec,
            selected: Selected::Mf,
            keys,
            certs,
            dg11,
            key: None,
        }
    }

    fn key(&self, reference: u8) -> Option<&EmuKey> {
        self.keys
            .iter()
            .find(|(r, _)| *r == reference)
            .map(|(_, k)| k)
    }

    fn select(&mut self, p1: u8, data: &[u8]) -> Reply {
        let next = match (p1, data, self.selected) {
            (0x00, [0x3F, 0x00], _) => Selected::Mf,
            (0x01, [0x01, 0x01], Selected::Mf) => Selected::Keys,
            (0x01, [0x08, 0x01], Selected::Mf) => Selected::Certs,
            (0x02, [0x01, n @ (0x01 | 0x02)], Selected::Certs) => Selected::Cert(*n),
            (0x02, [0x03, 0x01], Selected::Mf) if self.spec.id_card.is_some() => Selected::Iin,
            (0x04, [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01], _) if !self.dg11.is_empty() => {
                Selected::TravelDocument
            }
            _ => return sw(0x6A82),
        };
        self.selected = next;
        sw(0x9000)
    }

    fn read(&self, apdu: &Apdu) -> Reply {
        let (file, offset): (&[u8], usize) = if apdu.p1 & 0x80 != 0 {
            if apdu.p1 & 0x1F != 0x0B || self.selected != Selected::TravelDocument {
                return sw(0x6A82);
            }
            (&self.dg11, usize::from(apdu.p2))
        } else {
            let offset = usize::from(u16::from_be_bytes([apdu.p1, apdu.p2]));
            match self.selected {
                Selected::Cert(n) => (&self.certs[usize::from(n) - 1], offset),
                Selected::Iin => (
                    self.spec
                        .id_card
                        .as_ref()
                        .map_or(&[][..], |i| i.iin.as_bytes()),
                    offset,
                ),
                _ => return sw(0x6986),
            }
        };
        let len = apdu.le.map_or(0, |le| le as usize);
        match file.get(offset..) {
            Some(rest) if !rest.is_empty() => ok(rest[..len.min(rest.len())].to_vec()),
            _ => sw(0x6B00),
        }
    }

    fn public_key(&self, data: &[u8]) -> Reply {
        if self.selected != Selected::Keys {
            return sw(0x6985);
        }
        match data {
            [
                0x4D,
                0x09,
                0xFF,
                0xA0,
                sdo,
                0x05,
                0x7F,
                0x49,
                0x02,
                0x81,
                0x00,
            ] => {
                let Some(key) = self.key(sdo | 0x80) else {
                    return sw(0x6A88);
                };
                let mut out = vec![
                    0xFF, 0xA0, *sdo, 0x82, 0x01, 0x0D, 0x7F, 0x49, 0x82, 0x01, 0x09, 0x81, 0x82,
                    0x01, 0x00,
                ];
                out.extend(soft::rsa_modulus_be(&key.entry));
                out.extend([0x82, 0x03, 0x01, 0x00, 0x01]);
                ok(out)
            }
            [
                0x4D,
                0x09,
                0xFF,
                0xA2,
                r,
                0x05,
                0x7F,
                0x4E,
                0x02,
                0x86,
                0x00,
            ] => {
                let Some(key) = self.key(*r) else {
                    return sw(0x6A88);
                };
                let mut out = vec![
                    0xFF, 0xA2, *r, 0x81, 0x85, 0x7F, 0x4E, 0x81, 0x82, 0x86, 0x81, 0x80,
                ];
                out.extend(reverse_halves(&soft::gost_point_le(&key.entry)));
                ok(out)
            }
            _ => sw(0x6A80),
        }
    }

    fn mse(&mut self, p2: u8, data: &[u8]) -> Reply {
        let alg = if p2 == 0xA4 { 0x02 } else { 0x74 };
        let [0x95, 0x01, 0x40, 0x84, 0x01, reference, 0x80, 0x01, a] = data else {
            return sw(0x6A80);
        };
        if *a != alg {
            return sw(0x6A80);
        }
        if self.spec.id_card_2020 && reference & 0x80 != 0 {
            return sw(0x6A80);
        }
        let reference = if alg == 0x02 {
            reference | 0x80
        } else {
            *reference
        };
        if self.key(reference).is_none() {
            return sw(0x6A88);
        }
        self.key = Some(reference);
        sw(0x9000)
    }

    fn sign(&mut self, rsa: bool, data: &[u8]) -> Reply {
        if !self.pin.is_verified() {
            return sw(0x6982);
        }
        let Some(key) = self.key.and_then(|r| self.key(r)) else {
            return sw(0x6985);
        };
        if (key.entry.key.alg() == KeyAlg::Rsa) != rsa {
            return sw(0x6985);
        }
        if rsa {
            return ok(soft::rsa_sign_digest_info(&key.entry, data));
        }
        let mut sig = soft::gost_sign(&key.entry, &reversed(data), self.spec.fixed_k.as_deref());
        if self.spec.swap_signature_halves {
            soft::swap_halves(&mut sig);
        }
        ok(reverse_halves(&sig))
    }
}

impl Applet for KzIdCard {
    fn handle(&mut self, apdu: &Apdu) -> Reply {
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x00, 0xCA, 0xDF, 0x01) => {
                let mut id = self.spec.serial.to_vec();
                id.push(0x01);
                ok(id)
            }
            (0x00, 0xA4, p1, 0x0C) => self.select(p1, &apdu.data),
            (0x00, 0xB0, _, _) => self.read(apdu),
            (0x00, 0x20, 0x00, 0x02) => {
                if apdu.data.is_empty() {
                    // The PIN's state, no try spent.
                    return if self.pin.is_verified() {
                        sw(0x9000)
                    } else if self.pin.is_blocked() {
                        sw(0x6984)
                    } else {
                        sw(0x63C0 | u16::from(self.pin.tries()))
                    };
                }
                if apdu.data.len() != 8 {
                    return sw(0x6700);
                }
                match self.pin.verify(&apdu.data) {
                    PinCheck::Ok => sw(0x9000),
                    PinCheck::Wrong(n) => sw(0x63C0 | u16::from(n)),
                    PinCheck::Blocked => sw(0x6984),
                }
            }
            (0x00, 0xCB, 0x3F, 0xFF) => self.public_key(&apdu.data),
            (0x00, 0x22, 0x41, p2 @ (0xA4 | 0xB6)) => self.mse(p2, &apdu.data),
            (0x00, 0x88, 0x02, 0x00) => self.sign(true, &apdu.data),
            (0x00, 0x2A, 0x9E, 0x9A) => self.sign(false, &apdu.data),
            _ => sw(0x6D00),
        }
    }

    fn reset(&mut self) {
        self.pin.reset();
        self.selected = Selected::Mf;
        self.key = None;
    }
}
