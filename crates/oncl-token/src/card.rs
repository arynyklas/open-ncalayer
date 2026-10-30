//! APDU exchange with a card over a [`Connection`]: the T=0 rules (case 4 sent as case 3,
//! GET RESPONSE chains, wrong-length resends), limits against a card that never stops
//! answering, and the optional trace.

use crate::apdu::{Command, Response};
use crate::backend::{Connection, Protocol};
use crate::error::TokenError;
use crate::{MAX_GET_RESPONSE, MAX_RESPONSE, TRACE_VAR};
use std::fmt::Write;
use zeroize::Zeroize;

/// A card on a connection.
pub struct Card<'c> {
    conn: &'c mut dyn Connection,
    trace: bool,
}

/// [`TRACE_VAR`] is `1`: the APDU trace goes to the log.
pub fn trace_enabled() -> bool {
    std::env::var_os(TRACE_VAR).is_some_and(|v| v == "1")
}

fn spaced_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

impl<'c> Card<'c> {
    /// A card on `conn`; with `trace`, every exchange is logged (PINs redacted).
    pub fn new(conn: &'c mut dyn Connection, trace: bool) -> Card<'c> {
        Card { conn, trace }
    }

    /// Protocol of the connection.
    pub fn protocol(&self) -> Protocol {
        self.conn.protocol()
    }

    /// ATR of the card.
    pub fn atr(&self) -> &[u8] {
        self.conn.atr()
    }

    /// Sends `cmd` and returns the whole response: under T=0 a case 4 command goes as case
    /// 3, `61xx` is followed by GET RESPONSE until the data is complete, `6Cxx` resends the
    /// command once with Le `xx`.
    ///
    /// # Errors
    ///
    /// [`TokenError::Transport`] for an extended APDU over T=0, a broken exchange, more than
    /// [`MAX_GET_RESPONSE`] GET RESPONSE commands or more than [`MAX_RESPONSE`] bytes;
    /// [`TokenError::CardRemoved`] when the card is gone.
    pub fn transmit(&mut self, cmd: &Command) -> Result<Response, TokenError> {
        let t0 = self.protocol() == Protocol::T0;
        if t0 && cmd.is_extended() {
            return Err(TokenError::Transport("extended APDU over T=0".to_owned()));
        }
        // Under T=0 the card's data comes through GET RESPONSE: a case 4 goes as case 3.
        let le = if t0 && !cmd.data.is_empty() {
            None
        } else {
            cmd.le
        };
        let mut resp = self.exchange(cmd, le)?;
        if resp.sw1() == 0x6C {
            let le = match resp.sw2() {
                0 => 256,
                n => u32::from(n),
            };
            resp = self.exchange(cmd, Some(le))?;
        }
        let mut data = std::mem::take(&mut resp.data);
        let mut sw = resp.sw;
        let mut requests = 0;
        while (sw >> 8) == 0x61 {
            if requests == MAX_GET_RESPONSE {
                return Err(TokenError::Transport(format!(
                    "the card still has data after {MAX_GET_RESPONSE} GET RESPONSE commands"
                )));
            }
            requests += 1;
            let le = match sw as u8 {
                0 => 256,
                n => u32::from(n),
            };
            let get_response = Command::new(0x00, 0xC0, 0x00, 0x00).with_le(le);
            let next = self.exchange(&get_response, get_response.le)?;
            data.extend(next.data);
            if data.len() > MAX_RESPONSE {
                return Err(TokenError::Transport(format!(
                    "the card answers more than {MAX_RESPONSE} bytes"
                )));
            }
            sw = next.sw;
        }
        Ok(Response { data, sw })
    }

    /// [`Card::transmit`], the data of a `9000` response.
    ///
    /// # Errors
    ///
    /// As [`Card::transmit`]; [`TokenError::Card`] with `op` for another status.
    pub fn expect(&mut self, cmd: &Command, op: &'static str) -> Result<Vec<u8>, TokenError> {
        let resp = self.transmit(cmd)?;
        if resp.is_ok() {
            Ok(resp.data)
        } else {
            Err(TokenError::Card { op, sw: resp.sw })
        }
    }

    /// READ BINARY of `len` bytes of the current EF from `offset`, 255 bytes per command.
    ///
    /// # Errors
    ///
    /// As [`Card::expect`]; [`TokenError::Malformed`] when the file ends early or the
    /// offset leaves the 15-bit range.
    pub fn read_binary(&mut self, offset: u16, len: usize) -> Result<Vec<u8>, TokenError> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let at = usize::from(offset) + out.len();
            let at = u16::try_from(at)
                .ok()
                .filter(|at| *at <= 0x7FFF)
                .ok_or_else(|| TokenError::Malformed(format!("READ BINARY offset {at}")))?;
            let n = (len - out.len()).min(255);
            let [hi, lo] = at.to_be_bytes();
            let chunk = self.expect(
                &Command::new(0x00, 0xB0, hi, lo).with_le(n as u32),
                "read binary",
            )?;
            if chunk.is_empty() || chunk.len() > n {
                return Err(TokenError::Malformed(format!(
                    "READ BINARY of {n} bytes returned {}",
                    chunk.len()
                )));
            }
            out.extend(chunk);
        }
        Ok(out)
    }

    fn exchange(&mut self, cmd: &Command, le: Option<u32>) -> Result<Response, TokenError> {
        if cmd.redact {
            // A PIN: the verification must not outlive the connection.
            self.conn.reset_on_disconnect();
        }
        let mut apdu = cmd.encode_with_le(le);
        let raw = self.conn.transmit(&apdu);
        if cmd.redact {
            apdu.zeroize();
        }
        if self.trace {
            log(cmd, le, &raw);
        }
        Response::parse(&raw?)
    }
}

fn log(cmd: &Command, le: Option<u32>, raw: &Result<Vec<u8>, crate::backend::BackendError>) {
    let header = spaced_hex(&[cmd.cla, cmd.ins, cmd.p1, cmd.p2]);
    let data = if cmd.redact {
        format!("<redacted {} bytes>", cmd.data.len())
    } else {
        spaced_hex(&cmd.data)
    };
    let le = le.map_or_else(|| "-".to_owned(), |le| le.to_string());
    match raw {
        Ok(raw) if raw.len() >= 2 => {
            let (body, sw) = raw.split_at(raw.len() - 2);
            tracing::info!(
                target: "oncl_token::apdu",
                "> {header} Lc={} [{data}] Le={le} < SW={:02X}{:02X} +{} bytes",
                cmd.data.len(),
                sw[0],
                sw[1],
                body.len(),
            );
        }
        Ok(raw) => tracing::info!(
            target: "oncl_token::apdu",
            "> {header} Lc={} [{data}] Le={le} < {} bytes, no status word",
            cmd.data.len(),
            raw.len(),
        ),
        Err(e) => tracing::info!(
            target: "oncl_token::apdu",
            "> {header} Lc={} [{data}] Le={le} < {e}",
            cmd.data.len(),
        ),
    }
}
