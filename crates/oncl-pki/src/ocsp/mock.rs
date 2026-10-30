//! An in-process OCSP responder for tests.

use super::asn1::{
    BasicOcspResponse, CertId, OcspRequest, OcspResponse, ResponseBytes, ResponseData, RevokedInfo,
    SingleResponse,
};
use super::{CertStatus, OCSP_RESPONSE, key_hash};
use crate::asn1util::{Enumerated, RawGeneralizedTime, format_generalized_time, unsigned};
use crate::http::{
    HttpError, HttpErrorKind, HttpMethod, HttpReply, HttpRequest, HttpTransport, request_in_url,
    text_reply,
};
use crate::oid;
use crate::pkcs12::KeyEntry;
use crate::testing::{another_key, signature_alg};
use der::asn1::{AnyRef, BitStringRef, IntRef, OctetStringRef};
use der::{Decode, Encode, Tag, TagNumber};
use spki::AlgorithmIdentifierRef;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

/// How [`MockOcsp`] spoils its answer.
///
/// `None` and `ByKeyResponderId` give a valid answer; so do `Hang` no longer than the
/// request timeout, `NoNextUpdate` younger than `ocsp::ALLOWED_PERIOD`, `ThisUpdateAhead`
/// within `ocsp::CLOCK_SKEW` and `ContentType` with `application/ocsp-response` (any case,
/// with parameters). Every other variant makes `ocsp::check` fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OcspTamper {
    /// A correct answer, the responder identified by name.
    None,
    /// The response is signed with another key of the responder's algorithm than the
    /// responder certificate's.
    WrongKey,
    /// The response carries no certificates.
    NoCerts,
    /// A correct answer, the responder identified by the SHA-1 of its key.
    ByKeyResponderId,
    /// The responder is identified by the name of its issuer, which no certificate of the
    /// response has as its subject.
    OtherResponderId,
    /// The `CertID` of the answer has another serial number (its lowest bit flipped).
    OtherCertId,
    /// The `ResponseData` has no `SingleResponse`.
    NoSingleResponse,
    /// thisUpdate two hours ago, nextUpdate an hour ago.
    Stale,
    /// thisUpdate in an hour, nextUpdate in two.
    FutureThisUpdate,
    /// thisUpdate this far ahead of now, nextUpdate an hour after it: a responder whose
    /// clock runs ahead.
    ThisUpdateAhead(Duration),
    /// thisUpdate `age` ago, no nextUpdate.
    NoNextUpdate {
        /// Age of thisUpdate.
        age: Duration,
    },
    /// HTTP status other than 200, `text/plain` body.
    HttpStatus(u16),
    /// A correct response with this `Content-Type`.
    ContentType(&'static str),
    /// HTTP 200 `application/ocsp-response` with a body that is not DER.
    Garbage,
    /// No answer for this long: past the request timeout an [`HttpError`] once the timeout
    /// has elapsed, else a correct answer after it.
    Hang(Duration),
}

/// An OCSP responder answering requests of any binding (GET, the NCA GET binding, POST)
/// with a successful `BasicOCSPResponse` signed with `responder`'s key and carrying its
/// certificate: the status set for the requested serial number (`good` for any other),
/// thisUpdate a minute ago, nextUpdate in an hour, and the request's extensions (its
/// nonce) echoed as the response's. The `CertID` is echoed with its hash algorithm.
/// Unreadable requests get HTTP 400. Every requested URL and every request read are
/// recorded.
pub struct MockOcsp {
    responder: KeyEntry,
    statuses: BTreeMap<Vec<u8>, CertStatus>,
    tamper: OcspTamper,
    calls: Mutex<Vec<String>>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl MockOcsp {
    /// A responder signing with `responder` (e.g. the synthetic `ocsp-gost2015`).
    pub fn new(responder: KeyEntry) -> Self {
        MockOcsp {
            responder,
            statuses: BTreeMap::new(),
            tamper: OcspTamper::None,
            calls: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The same responder, answering `status` for the serial number `serial_hex` (hex
    /// digits of either case; leading zeros do not matter).
    ///
    /// # Panics
    ///
    /// If `serial_hex` has a character that is not a hex digit.
    #[must_use]
    pub fn status(mut self, serial_hex: &str, status: CertStatus) -> Self {
        self.statuses.insert(serial_from_hex(serial_hex), status);
        self
    }

    /// The same responder, spoiling its answers as `tamper` says.
    #[must_use]
    pub fn tamper(self, tamper: OcspTamper) -> Self {
        MockOcsp { tamper, ..self }
    }

    /// URLs requested so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.lock_calls().clone()
    }

    /// The DER `OCSPRequest`s read so far, in order.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn lock_calls(&self) -> MutexGuard<'_, Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// DER `OCSPResponse` answering the DER `OCSPRequest` `request`.
    fn respond(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let der_error = |e: der::Error| e.to_string();
        let request = OcspRequest::from_der(request).map_err(der_error)?;
        let requested = request
            .tbs_request
            .request_list
            .first()
            .ok_or("empty request list")?
            .req_cert;
        let status = self
            .statuses
            .get(unsigned(requested.serial_number.as_bytes()))
            .copied()
            .unwrap_or(CertStatus::Good);
        let mut serial = requested.serial_number.as_bytes().to_vec();
        if self.tamper == OcspTamper::OtherCertId
            && let Some(last) = serial.last_mut()
        {
            *last ^= 1;
        }
        let cert_id = CertId {
            serial_number: IntRef::new(&serial).map_err(der_error)?,
            ..requested
        };

        let now = OffsetDateTime::now_utc();
        let hour = time::Duration::HOUR;
        let (this_update, next_update) = match self.tamper {
            OcspTamper::Stale => (now - 2 * hour, Some(now - hour)),
            OcspTamper::FutureThisUpdate => (now + hour, Some(now + 2 * hour)),
            OcspTamper::ThisUpdateAhead(ahead) => (now + ahead, Some(now + ahead + hour)),
            OcspTamper::NoNextUpdate { age } => (now - age, None),
            _ => (now - time::Duration::MINUTE, Some(now + hour)),
        };
        let produced_at = format_generalized_time(now);
        let this_update = format_generalized_time(this_update);
        let next_update = next_update.map(format_generalized_time);

        let revoked_info = match status {
            CertStatus::Revoked { time, reason } => RevokedInfo {
                revocation_time: RawGeneralizedTime(format_generalized_time(time).as_bytes()),
                revocation_reason: reason.map(Enumerated),
            }
            .to_der()
            .map_err(der_error)?,
            CertStatus::Good | CertStatus::Unknown => Vec::new(),
        };
        let cert_status = match status {
            CertStatus::Good => AnyRef::new(context(false, 0), &[]),
            CertStatus::Revoked { .. } => AnyRef::new(
                context(true, 1),
                AnyRef::from_der(&revoked_info).map_err(der_error)?.value(),
            ),
            CertStatus::Unknown => AnyRef::new(context(false, 2), &[]),
        }
        .map_err(der_error)?;

        let cert = &self.responder.cert;
        let (responder_tag, responder_id) = match self.tamper {
            OcspTamper::ByKeyResponderId => {
                let hash = key_hash(cert);
                (2, OctetStringRef::new(&hash).and_then(|h| h.to_der()))
            }
            OcspTamper::OtherResponderId => (1, cert.tbs_certificate().issuer().to_der()),
            _ => (1, cert.tbs_certificate().subject().to_der()),
        };
        let responder_id = responder_id.map_err(der_error)?;

        let responses = if self.tamper == OcspTamper::NoSingleResponse {
            Vec::new()
        } else {
            vec![SingleResponse {
                cert_id,
                cert_status,
                this_update: RawGeneralizedTime(this_update.as_bytes()),
                next_update: next_update
                    .as_deref()
                    .map(|t| RawGeneralizedTime(t.as_bytes())),
                single_extensions: None,
            }]
        };
        let tbs = ResponseData {
            version: None,
            responder_id: AnyRef::new(context(true, responder_tag), &responder_id)
                .map_err(der_error)?,
            produced_at: RawGeneralizedTime(produced_at.as_bytes()),
            responses,
            response_extensions: request.tbs_request.request_extensions,
        }
        .to_der()
        .map_err(der_error)?;

        let alg = signature_alg(self.responder.key.alg());
        let other_key;
        let signer = if self.tamper == OcspTamper::WrongKey {
            other_key = another_key(&self.responder.key);
            &other_key
        } else {
            &self.responder.key
        };
        let signature = signer.sign(alg, &tbs).map_err(|e| e.to_string())?;
        let basic = BasicOcspResponse {
            tbs_response_data: AnyRef::from_der(&tbs).map_err(der_error)?,
            signature_algorithm: AlgorithmIdentifierRef {
                oid: alg.signature_oid(),
                parameters: Some(AnyRef::NULL),
            },
            signature: BitStringRef::from_bytes(&signature).map_err(der_error)?,
            certs: (self.tamper != OcspTamper::NoCerts).then(|| vec![cert.clone()]),
        }
        .to_der()
        .map_err(der_error)?;
        OcspResponse {
            response_status: Enumerated(0),
            response_bytes: Some(ResponseBytes {
                response_type: oid::OCSP_BASIC,
                response: OctetStringRef::new(&basic).map_err(der_error)?,
            }),
        }
        .to_der()
        .map_err(der_error)
    }
}

impl HttpTransport for MockOcsp {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.lock_calls().push(request.url.to_owned());
        let timeout = request.opts.timeout;
        match self.tamper {
            OcspTamper::Hang(hang) => {
                thread::sleep(hang.min(timeout));
                if hang > timeout {
                    return Err(HttpError::new(HttpErrorKind::Timeout, "timed out"));
                }
            }
            OcspTamper::HttpStatus(status) => return Ok(text_reply(status, "tampered")),
            OcspTamper::Garbage => {
                return Ok(HttpReply {
                    status: 200,
                    content_type: Some(OCSP_RESPONSE.to_owned()),
                    location: None,
                    body: b"<html>not an OCSP response</html>".to_vec(),
                });
            }
            _ => {}
        }
        let der = match request.method {
            HttpMethod::Post => Some(request.body.to_vec()),
            HttpMethod::Get => request_in_url(request.url),
        };
        let Some(der) = der else {
            return Ok(text_reply(400, "request is not base64"));
        };
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(der.clone());
        let content_type = match self.tamper {
            OcspTamper::ContentType(content_type) => content_type,
            _ => OCSP_RESPONSE,
        };
        Ok(match self.respond(&der) {
            Ok(body) => HttpReply {
                status: 200,
                content_type: Some(content_type.to_owned()),
                location: None,
                body,
            },
            Err(e) => text_reply(400, &e),
        })
    }
}

/// A context-specific tag.
fn context(constructed: bool, number: u32) -> Tag {
    Tag::ContextSpecific {
        constructed,
        number: TagNumber(number),
    }
}

/// Unsigned big-endian bytes of hex digits, without leading zeros.
fn serial_from_hex(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex
        .chars()
        .map(|c| {
            c.to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .unwrap_or_else(|| panic!("serial {hex:?} is not hex"))
        })
        .collect();
    let (head, pairs) = digits.split_at(digits.len() % 2);
    let bytes: Vec<u8> = head
        .iter()
        .copied()
        .chain(pairs.chunks(2).map(|p| (p[0] << 4) | p[1]))
        .collect();
    unsigned(&bytes).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_hex_parsing() {
        assert_eq!(serial_from_hex("00aB01"), [0xab, 0x01]);
        assert_eq!(serial_from_hex("abc"), [0x0a, 0xbc]);
        assert_eq!(serial_from_hex("0"), [] as [u8; 0]);
    }
}
