//! An in-process CRL distribution point for tests.

use super::CertificateList;
use crate::asn1util::{Enumerated, unsigned};
use crate::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport, text_reply};
use crate::pkcs12::KeyEntry;
use crate::testing::{another_key, signature_alg};
use der::Encode;
use der::asn1::{Any, BitString, GeneralizedTime, OctetString, Uint, UtcTime};
use der::oid::{AssociatedOid, ObjectIdentifier};
use spki::AlgorithmIdentifierOwned;
use std::sync::{Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;
use x509_cert::certificate::Version;
use x509_cert::crl::{RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{CrlNumber, CrlReason};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;

/// Media type of a DER CRL (RFC 2585 §4.2).
const PKIX_CRL: &str = "application/pkix-crl";

/// A revoked serial number.
struct Entry {
    serial: Vec<u8>,
    time: OffsetDateTime,
    reason: Option<u8>,
}

/// A CRL distribution point answering every GET with a v2 CRL of `issuer`, signed with its
/// key: the revoked serial numbers set, a CRL number, thisUpdate a minute before the mock
/// was made and nextUpdate an hour after. Times are encoded to the second. A CRL bigger
/// than the request's size limit is an [`HttpError`]; POSTs get HTTP 405. Every requested
/// URL is recorded.
pub struct MockCrl {
    issuer: KeyEntry,
    revoked: Vec<Entry>,
    this_update: OffsetDateTime,
    next_update: Option<OffsetDateTime>,
    wrong_key: bool,
    extensions: Vec<Extension>,
    calls: Mutex<Vec<String>>,
}

impl MockCrl {
    /// A distribution point of the CA `issuer_key` (e.g. the synthetic
    /// `inter-gost2015.key`).
    pub fn new(issuer_key: KeyEntry) -> Self {
        let now = OffsetDateTime::now_utc();
        MockCrl {
            issuer: issuer_key,
            revoked: Vec::new(),
            this_update: now - time::Duration::MINUTE,
            next_update: Some(now + time::Duration::HOUR),
            wrong_key: false,
            extensions: Vec::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The same CRL, listing `serial` (unsigned big-endian bytes; leading zeros do not
    /// matter) as revoked at `time`, without a reason code.
    #[must_use]
    pub fn revoke(self, serial: &[u8], time: OffsetDateTime) -> Self {
        self.entry(serial, time, None)
    }

    /// The same CRL, listing `serial` as revoked at `time` for the CRLReason `reason`.
    #[must_use]
    pub fn revoke_with_reason(self, serial: &[u8], time: OffsetDateTime, reason: u8) -> Self {
        self.entry(serial, time, Some(reason))
    }

    fn entry(mut self, serial: &[u8], time: OffsetDateTime, reason: Option<u8>) -> Self {
        self.revoked.push(Entry {
            serial: unsigned(serial).to_vec(),
            time,
            reason,
        });
        self
    }

    /// The same CRL with this nextUpdate, or none.
    #[must_use]
    pub fn next_update(self, next_update: Option<OffsetDateTime>) -> Self {
        MockCrl {
            next_update,
            ..self
        }
    }

    /// The same CRL signed with another key of the issuer's algorithm.
    #[must_use]
    pub fn wrong_key(self) -> Self {
        MockCrl {
            wrong_key: true,
            ..self
        }
    }

    /// The same CRL with `extension` added to its CRL extensions (after the CRL Number),
    /// e.g. a deltaCRLIndicator.
    #[must_use]
    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// URLs requested so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.lock_calls().clone()
    }

    fn lock_calls(&self) -> MutexGuard<'_, Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The DER CRL, signed anew.
    ///
    /// # Panics
    ///
    /// If a revoked serial number is zero or longer than 20 bytes, a time is before 1970,
    /// or signing fails.
    pub fn der(&self) -> Vec<u8> {
        let alg = signature_alg(self.issuer.key.alg());
        let algorithm = AlgorithmIdentifierOwned {
            oid: alg.signature_oid(),
            parameters: Some(Any::null()),
        };
        let revoked: Vec<RevokedCert> = self
            .revoked
            .iter()
            .map(|entry| RevokedCert {
                serial_number: SerialNumber::new(&entry.serial).expect("serial number"),
                revocation_date: x509_time(entry.time),
                crl_entry_extensions: entry
                    .reason
                    .map(|reason| vec![extension(CrlReason::OID, false, &Enumerated(reason))]),
            })
            .collect();
        let one = Uint::new(&[1]).expect("1 is an INTEGER");
        let mut extensions = vec![extension(CrlNumber::OID, false, &CrlNumber(one))];
        extensions.extend(self.extensions.iter().cloned());
        let tbs: TbsCertList = TbsCertList {
            version: Version::V2,
            signature: algorithm.clone(),
            issuer: self.issuer.cert.tbs_certificate().subject().clone(),
            this_update: x509_time(self.this_update),
            next_update: self.next_update.map(x509_time),
            revoked_certificates: (!revoked.is_empty()).then_some(revoked),
            crl_extensions: Some(extensions),
        };
        let tbs_der = tbs.to_der().expect("TBSCertList encodes");
        let other_key;
        let signer = if self.wrong_key {
            other_key = another_key(&self.issuer.key);
            &other_key
        } else {
            &self.issuer.key
        };
        let signature = signer.sign(alg, &tbs_der).expect("issuer key signs");
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
        }
        .to_der()
        .expect("CertificateList encodes")
    }
}

impl HttpTransport for MockCrl {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.lock_calls().push(request.url.to_owned());
        if request.method == HttpMethod::Post {
            return Ok(text_reply(405, "GET only"));
        }
        let max_len = request.opts.max_len;
        let body = self.der();
        if u64::try_from(body.len()).map_or(true, |len| len > max_len) {
            return Err(HttpError::other(format!("body exceeds {max_len} bytes")));
        }
        Ok(HttpReply {
            status: 200,
            content_type: Some(PKIX_CRL.to_owned()),
            location: None,
            body,
        })
    }
}

/// A non-critical or critical extension with the DER of `value`.
fn extension(oid: ObjectIdentifier, critical: bool, value: &impl Encode) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().expect("extension value encodes"))
            .expect("extension value fits an OCTET STRING"),
    }
}

/// `time` to the second, as RFC 5280 encodes it: UTCTime through 2049, GeneralizedTime
/// after.
fn x509_time(time: OffsetDateTime) -> Time {
    let unix = std::time::Duration::from_secs(
        u64::try_from(time.unix_timestamp()).expect("time after 1970"),
    );
    if time.year() < 2050 {
        Time::UtcTime(UtcTime::from_unix_duration(unix).expect("UTCTime"))
    } else {
        Time::GeneralTime(GeneralizedTime::from_unix_duration(unix).expect("GeneralizedTime"))
    }
}
