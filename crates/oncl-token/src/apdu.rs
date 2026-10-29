//! Command and response APDUs (ISO/IEC 7816-4): short and extended encodings.

use crate::error::TokenError;

/// A command APDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data (`Lc` is its length).
    pub data: Vec<u8>,
    /// Expected response length, 1..=65536; `None` when no data is expected.
    pub le: Option<u32>,
    /// The data is secret (a PIN): the trace shows its length only.
    pub redact: bool,
}

impl Command {
    /// A case 1 command: header only.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Command {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
            redact: false,
        }
    }

    /// With command data.
    #[must_use]
    pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Command {
        self.data = data.into();
        self
    }

    /// With an expected response length.
    ///
    /// # Panics
    ///
    /// Unless `1 <= le <= 65536`.
    #[must_use]
    pub fn with_le(mut self, le: u32) -> Command {
        assert!((1..=65_536).contains(&le), "Le {le} out of range");
        self.le = Some(le);
        self
    }

    /// With the data hidden from the trace.
    #[must_use]
    pub fn redacted(mut self) -> Command {
        self.redact = true;
        self
    }

    /// The command needs the extended encoding: more than 255 data bytes or more than 256
    /// expected.
    pub fn is_extended(&self) -> bool {
        extended(self.data.len(), self.le)
    }

    /// The bytes on the wire. Short: `CLA INS P1 P2 [Lc data] [Le]`, Le 256 as `00`.
    /// Extended: `CLA INS P1 P2 00 [Lc_hi Lc_lo data] [Le_hi Le_lo]` (without data
    /// `00 Le_hi Le_lo`), Le 65536 as `00 00`.
    ///
    /// # Panics
    ///
    /// If the data is longer than 65535 bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_le(self.le)
    }

    /// [`Command::encode`] with another Le (the transport drops or corrects it).
    pub(crate) fn encode_with_le(&self, le: Option<u32>) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 9);
        out.extend([self.cla, self.ins, self.p1, self.p2]);
        if extended(self.data.len(), le) {
            out.push(0);
            if !self.data.is_empty() {
                let lc = u16::try_from(self.data.len()).expect("at most 65535 data bytes");
                out.extend(lc.to_be_bytes());
                out.extend(&self.data);
            }
            if let Some(le) = le {
                // 65536 wraps to 00 00.
                out.extend((le as u16).to_be_bytes());
            }
        } else {
            if !self.data.is_empty() {
                out.push(self.data.len() as u8);
                out.extend(&self.data);
            }
            if let Some(le) = le {
                // 256 wraps to 00.
                out.push(le as u8);
            }
        }
        out
    }
}

fn extended(lc: usize, le: Option<u32>) -> bool {
    lc > 255 || le.is_some_and(|le| le > 256)
}

/// A response APDU: data and status word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Response data.
    pub data: Vec<u8>,
    /// Status word `SW1 SW2`.
    pub sw: u16,
}

impl Response {
    /// Splits raw response bytes into data and status word.
    ///
    /// # Errors
    ///
    /// [`TokenError::Transport`] for fewer than two bytes.
    pub fn parse(raw: &[u8]) -> Result<Response, TokenError> {
        let Some(split) = raw.len().checked_sub(2) else {
            return Err(TokenError::Transport(format!(
                "a response of {} bytes has no status word",
                raw.len()
            )));
        };
        let (data, sw) = raw.split_at(split);
        Ok(Response {
            data: data.to_vec(),
            sw: u16::from_be_bytes([sw[0], sw[1]]),
        })
    }

    /// First status byte.
    pub fn sw1(&self) -> u8 {
        (self.sw >> 8) as u8
    }

    /// Second status byte.
    pub fn sw2(&self) -> u8 {
        self.sw as u8
    }

    /// Status `9000`.
    pub fn is_ok(&self) -> bool {
        self.sw == 0x9000
    }
}
