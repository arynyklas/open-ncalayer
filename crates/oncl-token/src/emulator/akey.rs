//! An emulated AKey: sessions, the login with its counter in the token information, the
//! object list (each key's certificate, public and private key labelled `nca_<id>_<alias>`,
//! plus an object of another application), object values, signing in 255-byte pieces.

use super::applet::{Apdu, Applet, Reply, ok, sw};
use super::soft::{self, PinCheck, PinState};
use super::{CardSpec, EmuKey};
use oncl_gost::CurveId;
use oncl_pki::key::KeyAlg;

const AID: [u8; 8] = [0x77, 0x11, 0xC1, 0x32, 0x09, 0x00, 0x00, 0x00];

struct Object {
    id: u16,
    ty: u16,
    descr: Vec<u8>,
    value: Vec<u8>,
    /// The key a private key object signs with.
    key: Option<EmuKey>,
}

pub(crate) struct AKey {
    spec: CardSpec,
    pin: PinState,
    selected: bool,
    session: bool,
    objects: Vec<Object>,
    list: Vec<u8>,
    list_at: usize,
    /// The object being read and how far.
    reading: Option<(u16, usize)>,
    /// Data to sign received so far, for a key.
    signing: Option<(u8, Vec<u8>)>,
}

fn attribute(ty: u32, value: &[u8]) -> Vec<u8> {
    let mut out = ty.to_be_bytes().to_vec();
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
    out
}

fn key_type(alg: KeyAlg) -> [u8; 4] {
    match alg {
        KeyAlg::Gost2004 => [0x30, 0x00, 0x00, 0x00],
        KeyAlg::Gost2015_512 => [0x03, 0x10, 0x32, 0xD4],
        KeyAlg::Rsa => [0x00, 0x00, 0x00, 0x00],
    }
}

fn descriptor(label: &str, alg: Option<KeyAlg>) -> Vec<u8> {
    let mut d = attribute(3, label.as_bytes());
    if let Some(alg) = alg {
        d.extend(attribute(0x100, &key_type(alg)));
    }
    d.extend(attribute(0x102, label.as_bytes()));
    d
}

/// The curve blob before a GOST point: a header, then p, a, b, q and the base point,
/// zero-padded to 328 or 648 bytes.
fn curve_blob(curve: CurveId) -> Vec<u8> {
    let (header, size): ([u8; 8], usize) = match curve {
        CurveId::Pkigovkz2004A => ([0, 0, 0, 8, 0, 0, 0, 1], 328),
        CurveId::Tc26_512A => ([0, 0, 0, 0x10, 0, 0, 0, 1], 648),
    };
    let n = curve.coord_len();
    let params = curve.params();
    let mut blob = header.to_vec();
    for v in [
        &params.p, &params.a, &params.b, &params.q, &params.gx, &params.gy,
    ] {
        let bytes = v.to_be_bytes();
        blob.extend(&bytes[bytes.len() - n..]);
    }
    blob.resize(size, 0);
    blob
}

fn public_value(key: &EmuKey) -> Vec<u8> {
    match key.entry.key.alg() {
        KeyAlg::Rsa => {
            let mut value = vec![0u8; 258];
            value[..2].copy_from_slice(&[0x08, 0x00]);
            value[255..258].copy_from_slice(&[0x01, 0x00, 0x01]);
            value.extend(soft::rsa_modulus_be(&key.entry));
            value
        }
        alg => {
            let curve = if alg == KeyAlg::Gost2004 {
                CurveId::Pkigovkz2004A
            } else {
                CurveId::Tc26_512A
            };
            let mut value = curve_blob(curve);
            let xy = soft::gost_point_le(&key.entry);
            let (x, y) = xy.split_at(xy.len() / 2);
            value.extend(x.iter().rev());
            value.extend(y.iter().rev());
            value
        }
    }
}

impl AKey {
    pub(crate) fn new(spec: CardSpec) -> AKey {
        let mut objects = Vec::new();
        // An object of another application first: not ours.
        objects.push(Object {
            id: 0x0001,
            ty: 3,
            descr: descriptor("Other application key", Some(KeyAlg::Rsa)),
            value: Vec::new(),
            key: None,
        });
        for (i, key) in spec.keys.iter().enumerate() {
            let label = format!("nca_{}_{}", i + 1, key.entry.alias);
            let alg = key.entry.key.alg();
            let base = 0x0100 + 0x10 * i as u16;
            let cert = der::Encode::to_der(&key.entry.cert).expect("a certificate encodes");
            objects.push(Object {
                id: base + 1,
                ty: 1,
                descr: descriptor(&label, None),
                value: cert,
                key: None,
            });
            objects.push(Object {
                id: base + 2,
                ty: 2,
                descr: descriptor(&label, Some(alg)),
                value: public_value(key),
                key: None,
            });
            objects.push(Object {
                id: base + 3,
                ty: 3,
                descr: descriptor(&label, Some(alg)),
                value: Vec::new(),
                key: Some(key.clone()),
            });
        }
        let mut list = (objects.len() as u16).to_be_bytes().to_vec();
        for o in &objects {
            list.extend(o.id.to_be_bytes());
            list.extend(o.ty.to_be_bytes());
            list.extend([0x00, 0x00]);
            list.extend((o.descr.len() as u16).to_be_bytes());
            list.extend(&o.descr);
        }
        AKey {
            pin: PinState::new(&spec.pin, spec.tries, spec.max_tries),
            spec,
            selected: false,
            session: false,
            objects,
            list,
            list_at: 0,
            reading: None,
            signing: None,
        }
    }

    fn token_info(&self) -> Vec<u8> {
        let mut info = vec![0u8; 0xB0];
        info[..16].copy_from_slice(b"OpenNCALayer emu");
        info[16..24].copy_from_slice(&self.spec.serial);
        info[24..32].copy_from_slice(&self.spec.serial);
        info[32..41].copy_from_slice(b"emu token");
        info[83] = self.spec.max_tries;
        info[85] = self.pin.tries();
        info
    }

    fn read(&mut self, id: u16) -> Reply {
        let Some(object) = self.objects.iter().find(|o| o.id == id) else {
            return sw(0x6A88);
        };
        if object.ty == 3 {
            return sw(0x6982);
        }
        let mut stream = (object.value.len() as u16).to_be_bytes().to_vec();
        stream.extend(&object.value);
        let at = match self.reading {
            Some((r, at)) if r == id && at < stream.len() => at,
            _ => 0,
        };
        let end = (at + 255).min(stream.len());
        self.reading = Some((id, end));
        ok(stream[at..end].to_vec())
    }

    fn sign(&mut self, alg: u8, object: u8, data: &[u8]) -> Reply {
        let Some(key) = self
            .objects
            .iter()
            .find(|o| o.ty == 3 && o.id as u8 == object)
            .and_then(|o| o.key.clone())
        else {
            return sw(0x6A88);
        };
        let key_alg = key.entry.key.alg();
        let expected = match (alg, key_alg) {
            (0x00, KeyAlg::Rsa) => 256,
            (0x01, KeyAlg::Gost2004) => 32,
            (0x02, KeyAlg::Gost2015_512) => 64,
            _ => return sw(0x6A80),
        };
        let mut got = match self.signing.take() {
            Some((o, got)) if o == object => got,
            _ => Vec::new(),
        };
        got.extend(data);
        if got.len() < expected {
            self.signing = Some((object, got));
            return sw(0x9000);
        }
        if got.len() > expected {
            return sw(0x6700);
        }
        if key_alg == KeyAlg::Rsa {
            return match soft::rsa_sign_block(&key.entry, &got) {
                Ok(sig) => ok(sig),
                Err(status) => sw(status),
            };
        }
        got.reverse();
        let mut sig = soft::gost_sign(&key.entry, &got, self.spec.fixed_k.as_deref());
        if self.spec.swap_signature_halves {
            soft::swap_halves(&mut sig);
        }
        sig.reverse();
        ok(sig)
    }
}

impl Applet for AKey {
    fn handle(&mut self, apdu: &Apdu) -> Reply {
        if (apdu.cla, apdu.ins, apdu.p1, apdu.p2) == (0x00, 0xA4, 0x04, 0x00) {
            self.selected = apdu.data == AID;
            self.session = false;
            return sw(if self.selected { 0x9000 } else { 0x6A82 });
        }
        if !self.selected {
            return sw(0x6D00);
        }
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x80, 0x03, 0x00, 0x00) => {
                self.session = true;
                self.pin.reset();
                self.list_at = 0;
                self.reading = None;
                ok(vec![0x00, 0x00, 0x00, 0x01, 0x00])
            }
            _ if !self.session => sw(0x6985),
            (0x80, 0x06, 0x00, 0x00) => {
                self.session = false;
                self.pin.reset();
                sw(0x9000)
            }
            (0x80, 0x0A, 0x00, 0x00) => ok(self.token_info()),
            (0x80, 0x07, 0x00, 0x00) => match self.pin.verify(&apdu.data) {
                PinCheck::Ok => sw(0x9000),
                PinCheck::Wrong(_) => sw(0x9C02),
                PinCheck::Blocked => sw(0x9C0C),
            },
            (0x80, 0x10, 0x00, 0x00) => {
                let end = (self.list_at + 255).min(self.list.len());
                let chunk = self.list[self.list_at..end].to_vec();
                self.list_at = end;
                ok(chunk)
            }
            (0x80, 0x0F, hi, lo) => self.read(u16::from_be_bytes([hi, lo])),
            (0x80, 0x12, alg, object) if self.pin.is_verified() => {
                self.sign(alg, object, &apdu.data.clone())
            }
            (0x80, 0x12, _, _) => sw(0x6982),
            _ => sw(0x6D00),
        }
    }

    fn reset(&mut self) {
        self.pin.reset();
        self.selected = false;
        self.session = false;
        self.list_at = 0;
        self.reading = None;
        self.signing = None;
    }
}
