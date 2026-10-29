//! An in-process TSA for tests.

use super::asn1::{MessageImprint, PkiStatusInfo, TimeStampReq, TimeStampResp, TstInfo};
use super::{BASICS_POLICY, TIMESTAMP_QUERY, TIMESTAMP_REPLY, TspError, TspHash, replace_token};
use crate::asn1util::{RawGeneralizedTime, format_generalized_time, unsigned};
use crate::cms::{SignOptions, sign_content};
use crate::http::{GetOptions, HttpError, HttpReply, HttpTransport, percent_decode, text_reply};
use crate::oid;
use crate::pkcs12::KeyEntry;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{AnyRef, IntRef, ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierRef;
use std::sync::{Mutex, PoisonError};
use time::OffsetDateTime;

/// How [`MockTsa`] spoils its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MockTamper {
    /// A correct answer.
    None,
    /// The nonce differs from the request's (in its lowest bit).
    Nonce,
    /// The nonce is negative: the request's octets without the sign octet and with the top
    /// bit set (for a request nonce whose top bit is set, its octets read as two's
    /// complement).
    NegativeNonce,
}

/// A TSA answering GET (NCA binding) and POST requests with a granted `TimeStampResp`: a
/// `TSTInfo` with the request's policy (or the basics one), message imprint and nonce, the
/// current time (or the one set with [`MockTsa::with_gen_time`]) and a serial counting the
/// requests, signed with `entry` through `cms::sign_content` as id-ct-TSTInfo. Unreadable
/// requests get HTTP 400, a POST of another content type HTTP 415. Every requested URL is
/// recorded. [`MockTsa::stamp_with_nonce`] stamps a CMS directly, as for another client.
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
                location: None,
                body,
            },
            Err(e) => text_reply(400, &e),
        }
    }

    /// Time-stamps signer `signer_index` of a DER or BER `ContentInfo{SignedData}` without
    /// a request, as a token another client asked for: the basics policy, a Streebog-512
    /// imprint of the signer's signature, serial 0 and the nonce INTEGER whose contents
    /// octets are `nonce` (minimal two's complement, so `[0x80]` is −128). Returns the CMS
    /// (DER) with the token as that signer's id-aa-timeStampToken; nothing is recorded in
    /// [`MockTsa::calls`].
    ///
    /// # Errors
    ///
    /// [`TspError::Cms`] for an invalid CMS; [`TspError::Malformed`] if there is no such
    /// signer or `nonce` is empty.
    pub fn stamp_with_nonce(
        &self,
        cms: &[u8],
        signer_index: usize,
        nonce: &[u8],
    ) -> Result<Vec<u8>, TspError> {
        if nonce.is_empty() {
            return Err(TspError::Malformed("empty nonce INTEGER".to_owned()));
        }
        replace_token(cms, signer_index, |signature| {
            let hash = TspHash::Streebog512;
            let imprint = hash.digest(signature);
            let message_imprint = MessageImprint {
                hash_algorithm: AlgorithmIdentifierRef {
                    oid: hash.oid(),
                    parameters: Some(AnyRef::NULL),
                },
                hashed_message: OctetStringRef::new(&imprint)?,
            };
            self.token(BASICS_POLICY, message_imprint, Some(IntRef::new(nonce)?), 0)
        })
    }

    /// DER `TimeStampResp` answering the DER `TimeStampReq` `request`.
    fn time_stamp(&self, request: &[u8], serial: u32) -> Result<Vec<u8>, String> {
        let req = TimeStampReq::from_der(request).map_err(|e| e.to_string())?;
        // Contents octets of the nonce INTEGER to echo; the request's nonce is unsigned.
        let nonce = req.nonce.map(|n| {
            let mut magnitude = n.as_bytes().to_vec();
            match self.tamper {
                MockTamper::None => uint_contents(&magnitude),
                MockTamper::Nonce => {
                    if let Some(last) = magnitude.last_mut() {
                        *last ^= 1;
                    }
                    uint_contents(&magnitude)
                }
                MockTamper::NegativeNonce => {
                    match magnitude.first_mut() {
                        Some(first) => *first |= 0x80,
                        None => magnitude.push(0x80),
                    }
                    magnitude
                }
            }
        });
        let der_error = |e: der::Error| e.to_string();
        let nonce = nonce
            .as_deref()
            .map(IntRef::new)
            .transpose()
            .map_err(der_error)?;
        let token = self
            .token(
                req.req_policy.unwrap_or(BASICS_POLICY),
                req.message_imprint,
                nonce,
                serial,
            )
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

    /// A token (DER `ContentInfo`) of a `TSTInfo` with `policy`, `message_imprint`, `nonce`,
    /// serial `serial` and the TSA's time.
    fn token(
        &self,
        policy: ObjectIdentifier,
        message_imprint: MessageImprint<'_>,
        nonce: Option<IntRef<'_>>,
        serial: u32,
    ) -> Result<Vec<u8>, TspError> {
        let now = self.gen_time.unwrap_or_else(OffsetDateTime::now_utc);
        let gen_time = format_generalized_time(now);
        // A leading 01 keeps the INTEGER positive and minimal.
        let mut serial_number = vec![1];
        serial_number.extend_from_slice(&serial.to_be_bytes());
        let tst_info = TstInfo {
            version: 1,
            policy,
            message_imprint,
            serial_number: IntRef::new(&serial_number)?,
            gen_time: RawGeneralizedTime(gen_time.as_bytes()),
            accuracy: None,
            ordering: None,
            nonce,
            tsa: None,
            extensions: None,
        }
        .to_der()?;
        let opts = SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: now,
        };
        Ok(sign_content(
            &self.entry,
            &oid::TST_INFO,
            &tst_info,
            true,
            &opts,
        )?)
    }
}

/// A mock server: the request options do not change what it answers.
impl HttpTransport for MockTsa {
    fn get_with(&self, url: &str, _: GetOptions) -> Result<HttpReply, HttpError> {
        let serial = self.record(url);
        let encoded = url.rsplit('/').next().unwrap_or_default();
        Ok(
            match percent_decode(encoded).and_then(|b| STANDARD.decode(b).ok()) {
                Some(request) => self.respond(&request, serial),
                None => text_reply(400, "request is not percent-encoded base64"),
            },
        )
    }

    fn post_with(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
        _: GetOptions,
    ) -> Result<HttpReply, HttpError> {
        let serial = self.record(url);
        if content_type != TIMESTAMP_QUERY {
            return Ok(text_reply(415, content_type));
        }
        Ok(self.respond(body, serial))
    }
}

/// Contents octets of the DER INTEGER equal to the unsigned big-endian `magnitude`: a `00`
/// sign octet before a set top bit, `00` for zero.
fn uint_contents(magnitude: &[u8]) -> Vec<u8> {
    match unsigned(magnitude) {
        [] => vec![0],
        m if m[0] & 0x80 != 0 => [&[0][..], m].concat(),
        m => m.to_vec(),
    }
}
