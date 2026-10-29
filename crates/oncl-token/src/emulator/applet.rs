//! The plumbing every emulated card shares: APDU parsing and the T=0 behaviour of a card
//! (data through `61xx` and GET RESPONSE, `6Cxx` for a wrong Le), around a family's applet.

use super::{CardSpec, SoftCard};
use crate::backend::Protocol;

/// A command APDU as a card parses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    /// Expected length; `Some(256)` for a short `00`, `Some(65536)` for an extended `00 00`.
    pub le: Option<u32>,
}

impl Apdu {
    /// Parses short and extended encodings; `None` for a malformed one.
    pub(crate) fn parse(raw: &[u8]) -> Option<Apdu> {
        let (header, body) = raw.split_at_checked(4)?;
        let mut apdu = Apdu {
            cla: header[0],
            ins: header[1],
            p1: header[2],
            p2: header[3],
            data: Vec::new(),
            le: None,
        };
        let short_le = |b: u8| if b == 0 { 256 } else { u32::from(b) };
        let ext_le = |hi: u8, lo: u8| match u16::from_be_bytes([hi, lo]) {
            0 => 65_536,
            n => u32::from(n),
        };
        match body {
            [] => {}
            [le] => apdu.le = Some(short_le(*le)),
            [0, hi, lo] => apdu.le = Some(ext_le(*hi, *lo)),
            [0, hi, lo, rest @ ..] => {
                let lc = usize::from(u16::from_be_bytes([*hi, *lo]));
                if lc == 0 || rest.len() < lc {
                    return None;
                }
                let (data, le) = rest.split_at(lc);
                apdu.data = data.to_vec();
                match le {
                    [] => {}
                    [hi, lo] => apdu.le = Some(ext_le(*hi, *lo)),
                    _ => return None,
                }
            }
            [lc, rest @ ..] => {
                let lc = usize::from(*lc);
                let data = rest.get(..lc)?;
                apdu.data = data.to_vec();
                match &rest[lc..] {
                    [] => {}
                    [le] => apdu.le = Some(short_le(*le)),
                    _ => return None,
                }
            }
        }
        Some(apdu)
    }
}

/// What an applet answers: data and status word.
pub(crate) type Reply = (Vec<u8>, u16);

/// A status word without data.
pub(crate) fn sw(sw: u16) -> Reply {
    (Vec::new(), sw)
}

/// Data with `9000`.
pub(crate) fn ok(data: Vec<u8>) -> Reply {
    (data, 0x9000)
}

/// A family's applet behind the common card plumbing.
pub(crate) trait Applet: Send {
    /// Response to a parsed command.
    fn handle(&mut self, apdu: &Apdu) -> Reply;
    /// Card reset: no PIN verified, nothing selected.
    fn reset(&mut self);
}

/// An applet as a [`SoftCard`].
pub(crate) struct Emulated<A> {
    applet: A,
    atr: Vec<u8>,
    protocol: Protocol,
    t0_quirks: bool,
    /// Data waiting for GET RESPONSE.
    pending: Vec<u8>,
}

impl<A: Applet + 'static> Emulated<A> {
    /// `applet` with the ATR, protocol and T=0 behaviour of `spec`.
    pub(crate) fn boxed(applet: A, spec: &CardSpec) -> Box<dyn SoftCard> {
        Box::new(Emulated {
            applet,
            atr: spec.atr(),
            protocol: spec.protocol,
            t0_quirks: spec.t0_quirks,
            pending: Vec::new(),
        })
    }
}

impl<A: Applet> Emulated<A> {
    fn reply(&mut self, apdu: &Apdu) -> Reply {
        if self.t0_quirks && apdu.cla == 0x00 && apdu.ins == 0xC0 {
            if self.pending.is_empty() {
                return sw(0x6985);
            }
            let n = apdu.le.map_or(0, |le| le as usize).min(self.pending.len());
            let data: Vec<u8> = self.pending.drain(..n).collect();
            return (data, more(self.pending.len()));
        }
        self.pending.clear();
        let (data, status) = self.applet.handle(apdu);
        if !self.t0_quirks || data.is_empty() {
            return (data, status);
        }
        match apdu.le {
            None => {
                self.pending = data;
                sw(more(self.pending.len()))
            }
            Some(le) if le as usize != data.len() && status == 0x9000 => {
                sw(0x6C00 | (data.len().min(256) as u16 & 0xFF))
            }
            Some(_) => (data, status),
        }
    }
}

/// `61xx` for `left` bytes still waiting, `9000` for none.
fn more(left: usize) -> u16 {
    if left == 0 {
        0x9000
    } else {
        0x6100 | (left.min(256) as u16 & 0xFF)
    }
}

impl<A: Applet> SoftCard for Emulated<A> {
    fn atr(&self) -> Vec<u8> {
        self.atr.clone()
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn process(&mut self, raw: &[u8]) -> Vec<u8> {
        let (mut data, status) = match Apdu::parse(raw) {
            Some(apdu) => self.reply(&apdu),
            None => sw(0x6700),
        };
        data.extend(status.to_be_bytes());
        data
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.applet.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_parse_cases() {
        let p = |raw: &[u8]| Apdu::parse(raw).map(|a| (a.data, a.le));
        assert_eq!(p(&[0x80, 0x40, 0, 0]), Some((vec![], None)));
        assert_eq!(p(&[0, 0xB0, 0, 0, 0]), Some((vec![], Some(256))));
        assert_eq!(p(&[0, 0x20, 0, 2, 2, 1, 2]), Some((vec![1, 2], None)));
        assert_eq!(p(&[0, 0x2A, 0, 0, 1, 9, 0xFF]), Some((vec![9], Some(255))));
        assert_eq!(
            p(&[0x80, 0x12, 0x28, 0, 0, 0x10, 0]),
            Some((vec![], Some(4096)))
        );
        let mut ext = vec![0x80, 0x14, 0x23, 0x24, 0, 0x01, 0x02];
        ext.extend([7; 258]);
        ext.extend([0x01, 0x02]);
        assert_eq!(p(&ext), Some((vec![7; 258], Some(258))));
        assert_eq!(p(&[0, 0x20, 0, 2, 3, 1]), None);
        assert_eq!(p(&[0, 0x20]), None);
    }
}
