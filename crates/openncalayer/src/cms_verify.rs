//! `cms-verify`: a CMS signature and the certificates of its signers — certification paths,
//! validity and revocation — as of a proven signing time.
//!
//! - Only a verified time-stamp token proves when a signature existed (its genTime), as in
//!   the ades engine of the original. Without one the validation time is now; a signingTime
//!   attribute is the signer's own claim and is reported, never trusted. A certificate that
//!   is expired or revoked now while signingTime lies inside its validity or before its
//!   revocation makes the result `INDETERMINATE: no proof of signing time`.
//! - Revocation: the signer by OCSP; every CA between the signer and the anchor by the CRL
//!   of its issuer, through the on-disk cache. OCSP responses and CRLs must be current at
//!   the wall clock, whatever the validation time. A revocation after the proven signing
//!   time does not invalidate the signature.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{self, VerifiedSigner};
use oncl_pki::crl::{self, CrlCache, CrlStatus};
use oncl_pki::http::HttpTransport;
use oncl_pki::info::{CertInfo, cert_info};
use oncl_pki::ocsp::{self, CertStatus};
use oncl_pki::pkix::{CaSet, PathError, build_path};
use oncl_pki::tsp::{TspError, verify_token_for};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The line before `OK` in a report made without [`Options::online`]: what `OK` does not
/// mean.
pub const NOT_CHECKED: &str = "not checked: revocation";

/// The last line when everything else holds but some revocation status is unknown.
pub const NO_REVOCATION_DATA: &str = "INDETERMINATE: revocation data unavailable";

/// The last line when a signature would only hold at the time its signer claims.
pub const NO_PROOF_OF_TIME: &str = "INDETERMINATE: no proof of signing time";

/// Where revocation data comes from.
pub struct Online<'a> {
    /// Transport of OCSP requests and CRL downloads.
    pub http: &'a dyn HttpTransport,
    /// CRL cache directory, normally `<data_dir>/crl`.
    pub crl_dir: PathBuf,
}

/// What `cms-verify` checks signer certificates against, and how.
pub struct Options<'a> {
    /// CAs certification paths are built through: the embedded NCA set or `--chain`.
    pub cas: CaSet,
    /// Revocation sources; `None` (`--offline`) checks no revocation.
    pub online: Option<Online<'a>>,
    /// The current time: the validation time of a signer without a verified time-stamp,
    /// and the time OCSP responses and CRLs must be current at.
    pub now: OffsetDateTime,
}

/// Verifies a CMS signature, PEM or DER/BER, over its encapsulated content or `content`,
/// and the certificate of every signer at its validation time: the genTime of its verified
/// time-stamp token, otherwise `opts.now`.
///
/// The report has a block per signer (numbered from 0, as in error messages):
/// - `signer <n>: CN=<cn>, IIN=<iin|->, alg=<SigAlg>, signingTime=<RFC 3339|->`;
/// - `timestamp: yes|no`: whether the signer carries a time-stamp token;
/// - `chain: <issuer CN> -> … -> <anchor CN>` or `chain: FAIL <PathError>`: the path
///   through `opts.cas` at the validation time, moved into the certificate's validity (its
///   own validity is the next line);
/// - `validity: ok at <RFC 3339>`, `validity: FAIL`, or `validity: not valid at <now>, no
///   proof of signing time (signingTime <RFC 3339>)` when only the signer's claim would
///   make it valid;
/// - with a token, `tsa chain: …` (the TSA certificate's path at genTime) or `tsa chain:
///   not checked (time-stamp does not verify)`;
/// - `revocation: good (ocsp)` (`good (ocsp, crl)` when CA certificates were checked by
///   CRL), `revocation: revoked <RFC 3339> (ocsp|crl)`, `revocation: revoked <RFC 3339>
///   after signing (ocsp|crl)`, `revocation: unavailable (<error>)` (followed by `, revoked
///   … after signing (…)` if such a revocation was found) or `revocation: not checked
///   (--offline)`.
///
/// The last line is `FAIL: <error>` with the first failure of a signature, time-stamp,
/// path, validity or revocation; otherwise [`NO_PROOF_OF_TIME`], then
/// [`NO_REVOCATION_DATA`], if any signer is so; otherwise `OK` (after [`NOT_CHECKED`]
/// without `opts.online`). Returns the report and whether it is `OK`.
pub fn cms_verify_report_with(
    input: &[u8],
    content: Option<&[u8]>,
    opts: &Options<'_>,
) -> (String, bool) {
    let mut report = String::new();
    let ok = match describe(input, content, opts, &mut report) {
        Ok(Verdict::Valid) => {
            if opts.online.is_none() {
                let _ = writeln!(report, "{NOT_CHECKED}");
            }
            let _ = writeln!(report, "OK");
            true
        }
        Ok(Verdict::NoRevocationData) => {
            let _ = writeln!(report, "{NO_REVOCATION_DATA}");
            false
        }
        Ok(Verdict::NoProofOfTime) => {
            let _ = writeln!(report, "{NO_PROOF_OF_TIME}");
            false
        }
        Err(e) => {
            let _ = writeln!(report, "FAIL: {e}");
            false
        }
    };
    (report, ok)
}

/// The certificates of a `--chain` file: every `CERTIFICATE` block of a PEM file, or one
/// DER certificate.
///
/// # Errors
///
/// A PEM block of another label, bad base64, or a certificate that does not parse.
pub fn parse_certificates(input: &[u8]) -> Result<Vec<Certificate>, String> {
    let Some(blocks) = pem_blocks(input)? else {
        return Ok(vec![cert::parse(input).map_err(|e| e.to_string())?]);
    };
    if let Some((label, _)) = blocks.iter().find(|(label, _)| label != "CERTIFICATE") {
        return Err(format!("PEM block {label} is not a CERTIFICATE"));
    }
    blocks
        .iter()
        .map(|(_, der)| cert::parse(der).map_err(|e| e.to_string()))
        .collect()
}

/// Outcome of a signer that did not fail, from best to worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Valid,
    NoRevocationData,
    NoProofOfTime,
}

/// Writes the signer blocks: the first failure is the error, otherwise the worst verdict.
fn describe(
    input: &[u8],
    content: Option<&[u8]>,
    opts: &Options<'_>,
    report: &mut String,
) -> Result<Verdict, String> {
    let der = pem_or_der(input)?;
    let signers = cms::verify(&der, content).map_err(|e| e.to_string())?;
    let mut failure = None;
    let mut verdict = Verdict::Valid;
    for (n, signer) in signers.iter().enumerate() {
        match describe_signer(n, signer, opts, report) {
            Ok(v) => verdict = verdict.max(v),
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    failure.map_or(Ok(verdict), Err)
}

/// Writes the block of signer `n`: its first failure is the error, otherwise its verdict.
fn describe_signer(
    n: usize,
    signer: &VerifiedSigner,
    opts: &Options<'_>,
    report: &mut String,
) -> Result<Verdict, String> {
    let mut failure = None;
    let mut verdict = Verdict::Valid;
    let info = cert_info(&signer.cert);
    let signing_time = signer.signing_time.map_or_else(|| "-".to_owned(), rfc3339);
    let _ = writeln!(
        report,
        "signer {n}: CN={}, IIN={}, alg={:?}, signingTime={signing_time}",
        info.subject_cn.as_deref().unwrap_or("-"),
        info.iin.as_deref().unwrap_or("-"),
        signer.sig_alg,
    );

    let token = signer.timestamp_token.as_ref().and_then(|token| {
        verify_token_for(token, &signer.signature)
            .map_err(|e| {
                failure.get_or_insert_with(|| match e {
                    TspError::ImprintMismatch => {
                        format!("time-stamp of signer {n} does not cover its signature")
                    }
                    e => format!("time-stamp of signer {n}: {e}"),
                });
            })
            .ok()
    });
    let stamped = if signer.timestamp_token.is_some() {
        "yes"
    } else {
        "no"
    };
    let _ = writeln!(report, "timestamp: {stamped}");

    // Only a verified time-stamp proves when the signature existed.
    let proven = token.as_ref().map(|(tst, _)| tst.gen_time);
    let at = proven.unwrap_or(opts.now);
    // The signer's claim, when nothing proves it: it would excuse expiry or revocation.
    let claimed = signer.signing_time.filter(|_| proven.is_none());

    let path = build_path(&signer.cert, &opts.cas, path_time(&info, at));
    let _ = writeln!(report, "chain: {}", chain_line(&path));
    if let Err(e) = &path {
        failure.get_or_insert_with(|| format!("certificate chain of signer {n}: {e}"));
    }

    if is_valid_at(&info, at) {
        let _ = writeln!(report, "validity: ok at {}", rfc3339(at));
    } else if let Some(claimed) = claimed.filter(|&t| is_valid_at(&info, t)) {
        let _ = writeln!(
            report,
            "validity: not valid at {}, no proof of signing time (signingTime {})",
            rfc3339(at),
            rfc3339(claimed)
        );
        verdict = verdict.max(Verdict::NoProofOfTime);
    } else {
        let _ = writeln!(report, "validity: FAIL");
        failure.get_or_insert_with(|| {
            format!("certificate of signer {n} is not valid at {}", rfc3339(at))
        });
    }

    match &token {
        Some((tst, tsa)) => {
            let tsa_path = build_path(tsa, &opts.cas, tst.gen_time);
            let _ = writeln!(report, "tsa chain: {}", chain_line(&tsa_path));
            if let Err(e) = &tsa_path {
                failure.get_or_insert_with(|| {
                    format!("time-stamp certificate chain of signer {n}: {e}")
                });
            }
        }
        None if signer.timestamp_token.is_some() => {
            let _ = writeln!(
                report,
                "tsa chain: not checked (time-stamp does not verify)"
            );
        }
        None => {}
    }

    let status = match (&opts.online, &path) {
        (None, _) => Status::NotChecked,
        (Some(online), Ok(path)) => revocation(path, at, &opts.cas, online, opts.now),
        (Some(_), Err(_)) => Status::Unavailable {
            why: "no certification path".to_owned(),
            after: None,
        },
    };
    let _ = write!(report, "revocation: ");
    match status {
        Status::Good { crl: false } => {
            let _ = writeln!(report, "good (ocsp)");
        }
        Status::Good { crl: true } => {
            let _ = writeln!(report, "good (ocsp, crl)");
        }
        Status::NotChecked => {
            let _ = writeln!(report, "not checked (--offline)");
        }
        Status::After(revoked) => {
            let _ = writeln!(report, "{}", revoked.after_signing());
        }
        Status::Unavailable { why, after } => {
            let _ = write!(report, "unavailable ({why})");
            if let Some(revoked) = after {
                let _ = write!(report, ", {}", revoked.after_signing());
            }
            let _ = writeln!(report);
            verdict = verdict.max(Verdict::NoRevocationData);
        }
        Status::Revoked(revoked) => {
            let (time, source) = (rfc3339(revoked.time), revoked.source);
            let _ = writeln!(report, "revoked {time} ({source})");
            if claimed.is_some_and(|t| t < revoked.time) {
                verdict = verdict.max(Verdict::NoProofOfTime);
            } else {
                failure.get_or_insert_with(|| match revoked.ca {
                    None => format!("certificate of signer {n} is revoked at {time} ({source})"),
                    Some(ca) => format!(
                        "CA certificate CN={ca} in the chain of signer {n} is revoked at {time} \
                         ({source})"
                    ),
                });
            }
        }
    }
    failure.map_or(Ok(verdict), Err)
}

/// Revocation status of a signer's certification path.
enum Status {
    /// The signer is good by OCSP and every CA below the anchor by CRL; `crl` tells whether
    /// there was such a CA.
    Good { crl: bool },
    /// A certificate of the path was revoked at or before the validation time.
    Revoked(Revoked),
    /// Every status is known; the earliest revocation found is after the validation time.
    After(Revoked),
    /// Some status is unknown: why, and the earliest revocation after the validation time
    /// found meanwhile.
    Unavailable { why: String, after: Option<Revoked> },
    /// `--offline`.
    NotChecked,
}

/// A revoked certificate of a signer's path.
struct Revoked {
    /// Revocation time.
    time: OffsetDateTime,
    /// `ocsp` or `crl`.
    source: &'static str,
    /// The CN of the CA, or `None` for the signer itself.
    ca: Option<String>,
}

impl Revoked {
    /// `revoked <time> after signing (<source>)`.
    fn after_signing(&self) -> String {
        format!(
            "revoked {} after signing ({})",
            rfc3339(self.time),
            self.source
        )
    }
}

/// Keeps the earlier of `earliest` and `revoked`.
fn keep_earliest(earliest: &mut Option<Revoked>, revoked: Revoked) {
    if earliest.as_ref().is_none_or(|e| revoked.time < e.time) {
        *earliest = Some(revoked);
    }
}

/// Revocation status of `path` (`[signer, issuer, …, anchor]`) for the validation time
/// `at`: the signer by OCSP, then each CA between it and the anchor by the CRL of its
/// issuer. Responses and CRLs must be current at `now`. A revocation at or before `at`
/// ends the check.
fn revocation(
    path: &[Certificate],
    at: OffsetDateTime,
    cas: &CaSet,
    online: &Online<'_>,
    now: OffsetDateTime,
) -> Status {
    let Some(issuer) = path.get(1) else {
        return Status::Unavailable {
            why: "signer certificate is a trust anchor".to_owned(),
            after: None,
        };
    };
    let mut why: Option<String> = None;
    let mut after: Option<Revoked> = None;

    match ocsp::check(&path[0], issuer, cas, online.http, now, ocsp::TIMEOUT) {
        Ok(CertStatus::Good) => {}
        Ok(CertStatus::Revoked { time, .. }) => {
            let revoked = Revoked {
                time,
                source: "ocsp",
                ca: None,
            };
            if time <= at {
                return Status::Revoked(revoked);
            }
            keep_earliest(&mut after, revoked);
        }
        Ok(CertStatus::Unknown) => {
            why = Some("OCSP responder does not know the certificate".to_owned());
        }
        Err(e) => why = Some(e.to_string()),
    }

    let cache = CrlCache::new(&online.crl_dir);
    for pair in path[1..].windows(2) {
        let (ca, issuer) = (&pair[0], &pair[1]);
        match crl::check(ca, issuer, &cache, online.http, now) {
            Ok(CrlStatus::Good) => {}
            Ok(CrlStatus::Revoked { time, .. }) => {
                let revoked = Revoked {
                    time,
                    source: "crl",
                    ca: Some(cert_name(ca)),
                };
                if time <= at {
                    return Status::Revoked(revoked);
                }
                keep_earliest(&mut after, revoked);
            }
            Err(e) => {
                why.get_or_insert_with(|| {
                    format!("CRL of CA certificate CN={}: {e}", cert_name(ca))
                });
            }
        }
    }

    match (why, after) {
        (Some(why), after) => Status::Unavailable { why, after },
        (None, Some(revoked)) => Status::After(revoked),
        (None, None) => Status::Good {
            crl: path.len() > 2,
        },
    }
}

/// Whether `t` is within the certificate's validity, bounds included.
fn is_valid_at(info: &CertInfo, t: OffsetDateTime) -> bool {
    info.not_before <= t && t <= info.not_after
}

/// Time to build the certificate's path at: `at` moved into its validity, so the path is
/// judged on the CAs and the certificate's own period on the validity line.
fn path_time(info: &CertInfo, at: OffsetDateTime) -> OffsetDateTime {
    // Not `clamp`: a hostile certificate may end before it starts.
    at.max(info.not_before).min(info.not_after)
}

/// `<issuer CN> -> … -> <anchor CN>` of a path (the certificate itself for a path of one),
/// or `FAIL <PathError>`.
fn chain_line(path: &Result<Vec<Certificate>, PathError>) -> String {
    match path {
        Ok(path) => path[1.min(path.len() - 1)..]
            .iter()
            .map(cert_name)
            .collect::<Vec<_>>()
            .join(" -> "),
        Err(e) => format!("FAIL {e:?}"),
    }
}

/// The subject CN of `cert`, or its whole subject without one.
fn cert_name(cert: &Certificate) -> String {
    cert_info(cert)
        .subject_cn
        .unwrap_or_else(|| cert.tbs_certificate().subject().to_string())
}

/// RFC 3339, or the formatting error (only for years beyond 9999).
fn rfc3339(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_else(|e| e.to_string())
}

/// The DER of a PEM input (the first block, any label), or the input as is.
fn pem_or_der(input: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    match pem_blocks(input)? {
        None => Ok(Cow::Borrowed(input)),
        Some(blocks) => blocks
            .into_iter()
            .next()
            .map(|(_, der)| Cow::Owned(der))
            .ok_or_else(|| "PEM: no block".to_owned()),
    }
}

/// A PEM block: its label and DER.
type PemBlock = (String, Vec<u8>);

/// The blocks of a PEM input, `None` if it does not start with a BEGIN line. Text between
/// blocks is ignored.
fn pem_blocks(input: &[u8]) -> Result<Option<Vec<PemBlock>>, String> {
    let text = input.trim_ascii_start();
    if !text.starts_with(b"-----BEGIN ") {
        return Ok(None);
    }
    let text = std::str::from_utf8(text).map_err(|_| "PEM is not ASCII text".to_owned())?;
    let mut blocks = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in text.lines().map(str::trim) {
        if let Some((_, body)) = open.as_mut() {
            if line.starts_with("-----END ") {
                let (label, body) = open.take().expect("a block is open");
                let der = STANDARD.decode(&body).map_err(|e| format!("PEM: {e}"))?;
                blocks.push((label, der));
            } else {
                body.push_str(line);
            }
        } else if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            open = Some((label.to_owned(), String::new()));
        }
    }
    if open.is_some() {
        return Err("PEM: no END line".to_owned());
    }
    Ok(Some(blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_detection() {
        assert_eq!(pem_or_der(b"\x30\x03").unwrap(), &b"\x30\x03"[..]);
        let pem = "\r\n-----BEGIN CMS-----\r\nMAM=\r\n-----END CMS-----\r\n";
        assert_eq!(pem_or_der(pem.as_bytes()).unwrap(), &b"\x30\x03"[..]);
        assert!(pem_or_der(b"-----BEGIN CMS-----\nMAM=\n").is_err());
        assert!(pem_or_der(b"-----BEGIN CMS-----\n!!\n-----END CMS-----\n").is_err());
    }

    #[test]
    fn pem_bundles() {
        let two = "-----BEGIN CERTIFICATE-----\nMAM=\n-----END CERTIFICATE-----\nnote\n\
                   -----BEGIN X-----\r\nMAQ=\r\n-----END X-----\n";
        assert_eq!(
            pem_blocks(two.as_bytes()).unwrap(),
            Some(vec![
                ("CERTIFICATE".to_owned(), vec![0x30, 0x03]),
                ("X".to_owned(), vec![0x30, 0x04]),
            ])
        );
        assert_eq!(
            parse_certificates(two.as_bytes()).unwrap_err(),
            "PEM block X is not a CERTIFICATE"
        );
        assert_eq!(pem_blocks(b"\x30\x03").unwrap(), None);
    }

    #[test]
    fn path_time_stays_in_validity() {
        let mut info =
            cert_info(&cert::parse(&oncl_testkit::synthetic_cert("root-gost2015")).unwrap());
        let (from, to) = (info.not_before, info.not_after);
        assert_eq!(path_time(&info, from - time::Duration::DAY), from);
        assert_eq!(path_time(&info, to + time::Duration::DAY), to);
        let inside = from + time::Duration::DAY;
        assert_eq!(path_time(&info, inside), inside);
        // A certificate that ends before it starts does not panic.
        (info.not_before, info.not_after) = (to, from);
        assert_eq!(path_time(&info, inside), from);
    }
}
