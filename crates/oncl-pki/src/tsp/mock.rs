//! An in-process TSA for tests.

use super::asn1::{PkiStatusInfo, TimeStampReq, TimeStampResp, TstInfo};
use super::{BASICS_POLICY, TIMESTAMP_QUERY, TIMESTAMP_REPLY};
use crate::asn1util::{RawGeneralizedTime, format_generalized_time};
use crate::cms::{SignOptions, sign_content};
use crate::http::{HttpError, HttpReply, HttpTransport, percent_decode, text_reply};
use crate::oid;
use crate::pkcs12::KeyEntry;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{AnyRef, IntRef, UintRef};
use der::{Decode, Encode};
use std::sync::{Mutex, PoisonError};
use time::OffsetDateTime;

/// How [`MockTsa`] spoils its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MockTamper {
    /// A correct answer.
    None,
    /// The nonce differs from the request's (in its lowest bit).
    Nonce,
}

/// A TSA answering GET (NCA binding) and POST requests with a granted `TimeStampResp`: a
/// `TSTInfo` with the request's policy (or the basics one), message imprint and nonce, the
/// current time (or the one set with [`MockTsa::with_gen_time`]) and a serial counting the
/// requests, signed with `entry` through `cms::sign_content` as id-ct-TSTInfo. Unreadable
/// requests get HTTP 400, a POST of another content type HTTP 415. Every requested URL is
/// recorded.
pub struct MockTsa {
    entry: KeyEntry,
    tamper: MockTamper,
    gen_time: Option<OffsetDateTime>,
    calls: Mutex<Vec<String>>,
}

impl MockTsa {
    /// A TSA signing with `entry` (e.g. the synthetic `tsa-gost2015`).
    pub fn new(entry: KeyEntry) -> Self {
        MockTsa {
            entry,
            tamper: MockTamper::None,
            gen_time: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The same TSA, spoiling its answers as `tamper` says.
    #[must_use]
    pub fn with_tamper(self, tamper: MockTamper) -> Self {
        MockTsa { tamper, ..self }
    }

    /// The same TSA with a stopped clock: every token has `gen_time` (to the second) as its
    /// genTime and signingTime.
    #[must_use]
    pub fn with_gen_time(self, gen_time: OffsetDateTime) -> Self {
        MockTsa {
            gen_time: Some(gen_time),
            ..self
        }
    }

    /// URLs requested so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.lock_calls().clone()
    }

    fn lock_calls(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `url`, returning the request's serial number (1, 2, …).
    fn record(&self, url: &str) -> u32 {
        let mut calls = self.lock_calls();
        calls.push(url.to_owned());
        u32::try_from(calls.len()).unwrap_or(u32::MAX)
    }

    fn respond(&self, request: &[u8], serial: u32) -> HttpReply {
        match self.time_stamp(request, serial) {
            Ok(body) => HttpReply {
                status: 200,
                content_type: Some(TIMESTAMP_REPLY.to_owned()),
                body,
            },
            Err(e) => text_reply(400, &e),
        }
    }

    /// DER `TimeStampResp` answering the DER `TimeStampReq` `request`.
    fn time_stamp(&self, request: &[u8], serial: u32) -> Result<Vec<u8>, String> {
        let req = TimeStampReq::from_der(request).map_err(|e| e.to_string())?;
        let mut nonce = req.nonce.map(|n| n.as_bytes().to_vec());
        if self.tamper == MockTamper::Nonce
            && let Some(last) = nonce.as_mut().and_then(|n| n.last_mut())
        {
            *last ^= 1;
        }
        let now = self.gen_time.unwrap_or_else(OffsetDateTime::now_utc);
        let gen_time = format_generalized_time(now);
        // A leading 01 keeps the INTEGER positive and minimal.
        let mut serial_number = vec![1];
        serial_number.extend_from_slice(&serial.to_be_bytes());
        let der_error = |e: der::Error| e.to_string();
        let tst_info = TstInfo {
            version: 1,
            policy: req.req_policy.unwrap_or(BASICS_POLICY),
            message_imprint: req.message_imprint,
            serial_number: IntRef::new(&serial_number).map_err(der_error)?,
            gen_time: RawGeneralizedTime(gen_time.as_bytes()),
            accuracy: None,
            ordering: None,
            nonce: nonce
                .as_deref()
                .map(UintRef::new)
                .transpose()
                .map_err(der_error)?,
            tsa: None,
            extensions: None,
        }
        .to_der()
        .map_err(der_error)?;
        let opts = SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: now,
        };
        let token = sign_content(&self.entry, &oid::TST_INFO, &tst_info, true, &opts)
            .map_err(|e| e.to_string())?;
        TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(AnyRef::from_der(&token).map_err(der_error)?),
        }
        .to_der()
        .map_err(der_error)
    }
}

impl HttpTransport for MockTsa {
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        let serial = self.record(url);
        let encoded = url.rsplit('/').next().unwrap_or_default();
        Ok(
            match percent_decode(encoded).and_then(|b| STANDARD.decode(b).ok()) {
                Some(request) => self.respond(&request, serial),
                None => text_reply(400, "request is not percent-encoded base64"),
            },
        )
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, HttpError> {
        let serial = self.record(url);
        if content_type != TIMESTAMP_QUERY {
            return Ok(text_reply(415, content_type));
        }
        Ok(self.respond(body, serial))
    }
}
