//! The server certificate issued with mkcert's CA (<https://github.com/FiloSottile/mkcert>),
//! for users who already trust it.
//!
//! mkcert keeps its CA in `CAROOT`: `rootCA.pem` (the certificate) and `rootCA-key.pem` (its
//! PKCS#8 key, unencrypted). [`issue_with_mkcert`] reads the key only while it signs, keeps it
//! zeroized in memory and never writes it: only the leaf, its own key and the (public) CA
//! certificate are saved.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use der::{Encode, Tag, Tagged};
use rcgen::string::{BmpString, Ia5String, PrintableString};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, Issuer, KeyIdMethod, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use time::{Duration, OffsetDateTime, UtcOffset};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::{BasicConstraints, SubjectKeyIdentifier};
use x509_cert::name::Name;
use zeroize::Zeroizing;

use crate::generate::{BACKDATE, LEAF_VALIDITY_DAYS, gen_err, leaf_params};
use crate::{Renewal, TargetOs, TlsError, TlsFiles, TlsInfo, TlsMaterial, TlsSource};

/// mkcert's CA certificate in `CAROOT`.
const ROOT_CERT: &str = "rootCA.pem";
/// mkcert's CA key in `CAROOT`.
const ROOT_KEY: &str = "rootCA-key.pem";

/// mkcert's CA directory, if it has a CA certificate: `$CAROOT`, else where `mkcert
/// -CAROOT` puts it by default (`%LOCALAPPDATA%\mkcert`; `$XDG_DATA_HOME/mkcert`;
/// `~/Library/Application Support/mkcert` on macOS; `~/.local/share/mkcert`).
pub fn mkcert_caroot() -> Option<PathBuf> {
    caroot_of(TargetOs::current(), |name| std::env::var_os(name))
        .filter(|dir| dir.join(ROOT_CERT).is_file())
}

/// mkcert's `getCAROOT` for `os` with the environment `var`: empty variables count as unset.
fn caroot_of(os: TargetOs, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let var = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(caroot) = var("CAROOT") {
        return Some(caroot);
    }
    let base = if os == TargetOs::Windows {
        var("LOCALAPPDATA")?
    } else if let Some(data) = var("XDG_DATA_HOME") {
        data
    } else if os == TargetOs::MacOs {
        var("HOME")?.join("Library").join("Application Support")
    } else {
        var("HOME")?.join(".local").join("share")
    };
    Some(base.join("mkcert"))
}

/// Issues a server leaf for `127.0.0.1`, `::1` and `localhost` signed by mkcert's CA in
/// `caroot`, valid from an hour before `now` for at most 800 days (and not past the CA).
///
/// The CA key `rootCA-key.pem` is read here and zeroized before this returns; the material
/// holds the CA certificate (public) but never its key. The leaf is checked to chain to the
/// CA (webpki) before it is returned.
///
/// # Errors
///
/// [`TlsError::Mkcert`]: a file is missing or unreadable, the key does not belong to the
/// certificate, the certificate is not a CA or not valid at `now`, or its name cannot be
/// reproduced.
pub fn issue_with_mkcert(caroot: &Path, now: OffsetDateTime) -> Result<TlsMaterial, TlsError> {
    issue(caroot, now, None)
}

/// What [`renew_with_mkcert`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MkcertRenewal {
    /// The certificate in the files is not (or no longer) one issued with mkcert's CA, with
    /// the consent, and due for the automatic re-issue ([`crate::needs_renewal`]): nothing
    /// was read from `CAROOT` and nothing was written.
    NotDue,
    /// Re-issued with the CA that issued the previous certificate and saved, keeping the
    /// recorded consent: the new metadata.
    Renewed(TlsInfo),
}

/// Why [`renew_with_mkcert`] did not renew.
#[derive(Debug, thiserror::Error)]
pub enum RenewError {
    /// mkcert's CA cannot be used ([`TlsError::Mkcert`]), or `rootCA.pem` is not the CA that
    /// issued the certificate in use ([`TlsError::MkcertCaChanged`]; its key was not read).
    /// Nothing was written.
    #[error(transparent)]
    Issue(TlsError),
    /// The new certificate could not be saved; the files may be half written.
    #[error("{0}")]
    Save(io::Error),
}

/// Re-issues the mkcert certificate in `files` at `now` if it is due for the automatic
/// re-issue with the user's consent ([`crate::needs_renewal`]) and saves it, keeping the
/// recorded consent.
///
/// Everything runs while no other save, consent change or server configuration read of this
/// process runs: a consent withdrawn ([`crate::set_mkcert_consent`]) before is honoured
/// ([`MkcertRenewal::NotDue`]), one withdrawn meanwhile waits and then applies to the new
/// certificate. The SHA-256 of `rootCA.pem` is compared with [`TlsInfo::ca_sha256`] before
/// `rootCA-key.pem` is touched: the consent covers the key of the CA that issued the
/// certificate, not of whatever CA is in `CAROOT` now.
///
/// # Errors
///
/// See [`RenewError`]; the certificate in use is left as it is.
pub fn renew_with_mkcert(
    files: &TlsFiles,
    now: OffsetDateTime,
) -> Result<MkcertRenewal, RenewError> {
    renew_while_locked(files, now, || {})
}

/// [`renew_with_mkcert`]; `before_save` runs with the files locked, right before the save.
fn renew_while_locked(
    files: &TlsFiles,
    now: OffsetDateTime,
    before_save: impl FnOnce(),
) -> Result<MkcertRenewal, RenewError> {
    let _files = crate::files::lock();
    let Ok(Some(info)) = crate::files::load_info(files) else {
        return Ok(MkcertRenewal::NotDue);
    };
    let (Renewal::AutoRenew, TlsSource::Mkcert { caroot, .. }) =
        (crate::needs_renewal(&info, now), &info.source)
    else {
        return Ok(MkcertRenewal::NotDue);
    };
    let mut material = issue(
        caroot,
        now,
        Some(info.ca_sha256.as_deref().unwrap_or_default()),
    )
    .map_err(RenewError::Issue)?;
    // The consent was given once, for every renewal.
    material.info.source = info.source.clone();
    before_save();
    crate::files::save_locked(files, &material).map_err(RenewError::Save)?;
    Ok(MkcertRenewal::Renewed(material.info))
}

/// [`issue_with_mkcert`]; with `expected_ca`, the lowercase hex SHA-256 of the CA that must be
/// in `rootCA.pem`, any other CA is refused before its key is read.
fn issue(
    caroot: &Path,
    now: OffsetDateTime,
    expected_ca: Option<&str>,
) -> Result<TlsMaterial, TlsError> {
    let now = now
        .to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    let cert_path = caroot.join(ROOT_CERT);
    let ca_pem = fs::read(&cert_path).map_err(|e| mkcert_err(&cert_path, e))?;
    let ca_der = CertificateDer::from_pem_slice(&ca_pem).map_err(|e| mkcert_err(&cert_path, e))?;
    if expected_ca.is_some_and(|expected| crate::sha256_hex(&ca_der) != expected) {
        return Err(TlsError::MkcertCaChanged(cert_path.display().to_string()));
    }
    let ca = Certificate::from_der(&ca_der).map_err(|e| mkcert_err(&cert_path, e))?;
    let tbs = ca.tbs_certificate();
    let is_ca = tbs
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca);
    if !is_ca {
        return Err(mkcert_err(&cert_path, "not a CA certificate"));
    }
    let validity = tbs.validity();
    let ca_not_before = to_time(&validity.not_before);
    let ca_not_after = to_time(&validity.not_after);
    if now < ca_not_before || now >= ca_not_after {
        return Err(mkcert_err(
            &cert_path,
            format!("the CA is valid from {ca_not_before} to {ca_not_after}, not at {now}"),
        ));
    }
    let ski = tbs
        .get_extension::<SubjectKeyIdentifier>()
        .ok()
        .flatten()
        .map(|(_, ski)| ski.0.as_bytes().to_vec());
    let subject = distinguished_name(tbs.subject()).map_err(|e| mkcert_err(&cert_path, e))?;

    let key_path = caroot.join(ROOT_KEY);
    let ca_key = {
        let pem =
            Zeroizing::new(fs::read_to_string(&key_path).map_err(|e| mkcert_err(&key_path, e))?);
        Zeroizing::new(KeyPair::from_pem(&pem).map_err(|e| mkcert_err(&key_path, e))?)
    };
    let ca_public = tbs.subject_public_key_info().subject_public_key.raw_bytes();
    if ca_key.public_key_raw() != ca_public {
        return Err(mkcert_err(
            &key_path,
            format!("the key does not belong to {ROOT_CERT}"),
        ));
    }

    let not_before = now - BACKDATE;
    let not_after = (not_before + Duration::days(LEAF_VALIDITY_DAYS)).min(ca_not_after);
    let mut leaf = leaf_params(not_before, not_after)?;
    leaf.use_authority_key_identifier_extension = ski.is_some();
    let mut issuer = CertificateParams::default();
    issuer.distinguished_name = subject;
    issuer.key_identifier_method = KeyIdMethod::PreSpecified(ski.unwrap_or_default());
    let leaf_key = Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(gen_err)?);
    let leaf_cert = leaf
        .signed_by(&*leaf_key, &Issuer::new(issuer, &*ca_key))
        .map_err(gen_err)?;
    // The CA key is not needed any more: zeroize it now rather than at the end of scope.
    drop(ca_key);
    chains_to(&ca, &ca_der, leaf_cert.der(), now).map_err(|e| mkcert_err(&cert_path, e))?;

    let info = TlsInfo {
        source: TlsSource::Mkcert {
            caroot: caroot.to_path_buf(),
            consented_at: Some(crate::rfc3339(now).map_err(TlsError::Gen)?),
        },
        ca_sha1: Some(crate::sha1_hex(&ca_der)),
        ca_sha256: Some(crate::sha256_hex(&ca_der)),
        leaf_sha256: crate::sha256_hex(leaf_cert.der()),
        leaf_not_after: crate::rfc3339(not_after).map_err(TlsError::Gen)?,
        created_at: crate::rfc3339(now).map_err(TlsError::Gen)?,
        generator: crate::generator(),
    };
    Ok(TlsMaterial {
        chain_pem: leaf_cert.pem(),
        key_pem: Zeroizing::new(leaf_key.serialize_pem()),
        // Re-encoded: only the certificate, whatever else `rootCA.pem` may hold.
        ca_pem: Some(
            der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, &ca_der)
                .map_err(|e| mkcert_err(&cert_path, e))?,
        ),
        ca_der: Some(ca_der.to_vec()),
        info,
        warnings: Vec::new(),
    })
}

fn mkcert_err(path: &Path, e: impl std::fmt::Display) -> TlsError {
    TlsError::Mkcert(format!("{}: {e}", path.display()))
}

/// `name` as rcgen writes it again: the same attributes in the same order with the same
/// string types. A name rcgen cannot write the same way (several attributes in one RDN, a
/// repeated attribute type, another string type) is an error.
fn distinguished_name(name: &Name) -> Result<DistinguishedName, String> {
    let mut dn = DistinguishedName::new();
    let mut count = 0;
    for rdn in name.iter_rdn() {
        let mut attributes = rdn.iter();
        let (Some(attribute), None) = (attributes.next(), attributes.next()) else {
            return Err("a name with several attributes in one RDN".to_owned());
        };
        let oid: Vec<u64> = attribute.oid.arcs().map(u64::from).collect();
        let value = &attribute.value;
        let text = || std::str::from_utf8(value.value()).map_err(|e| e.to_string());
        let value = match value.tag() {
            Tag::Utf8String => DnValue::Utf8String(text()?.to_owned()),
            Tag::PrintableString => DnValue::PrintableString(
                PrintableString::try_from(text()?).map_err(|e| e.to_string())?,
            ),
            Tag::Ia5String => {
                DnValue::Ia5String(Ia5String::try_from(text()?).map_err(|e| e.to_string())?)
            }
            Tag::BmpString => DnValue::BmpString(
                BmpString::from_utf16be(value.value().to_vec()).map_err(|e| e.to_string())?,
            ),
            tag => return Err(format!("a name attribute of type {tag}")),
        };
        dn.push(DnType::from_oid(&oid), value);
        count += 1;
    }
    if dn.iter().count() != count {
        return Err("a name with a repeated attribute type".to_owned());
    }
    Ok(dn)
}

/// Whether `leaf_der` names `ca` as its issuer byte for byte and verifies under it for a TLS
/// server `127.0.0.1` at `now`.
fn chains_to(
    ca: &Certificate,
    ca_der: &CertificateDer<'_>,
    leaf_der: &CertificateDer<'_>,
    now: OffsetDateTime,
) -> Result<(), String> {
    let leaf = Certificate::from_der(leaf_der).map_err(|e| e.to_string())?;
    let issuer = leaf.tbs_certificate().issuer().to_der();
    let subject = ca.tbs_certificate().subject().to_der();
    if issuer.is_err() || issuer != subject {
        return Err("the CA name cannot be reproduced in the certificate".to_owned());
    }
    let anchor = webpki::anchor_from_trusted_cert(ca_der).map_err(|e| e.to_string())?;
    let end_entity = webpki::EndEntityCert::try_from(leaf_der).map_err(|e| e.to_string())?;
    let at = u64::try_from(now.unix_timestamp())
        .map(|secs| UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs)))
        .map_err(|e| e.to_string())?;
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &[],
            at,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| format!("the certificate does not verify under the CA: {e}"))?;
    end_entity
        .verify_is_valid_for_subject_name(&ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
        .map_err(|e| e.to_string())
}

fn to_time(t: &x509_cert::time::Time) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + t.to_unix_duration()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn caroot_follows_mkcert() {
        let p = |s: &str| Some(PathBuf::from(s));
        let all = [
            ("CAROOT", "/ca"),
            ("LOCALAPPDATA", r"C:\Users\a\AppData\Local"),
            ("XDG_DATA_HOME", "/xdg"),
            ("HOME", "/home/a"),
        ];
        for os in [TargetOs::Windows, TargetOs::MacOs, TargetOs::Linux] {
            assert_eq!(caroot_of(os, env(&all)), p("/ca"), "{os:?}");
            assert_eq!(caroot_of(os, env(&[])), None, "{os:?}");
        }
        let no_caroot = &all[1..];
        assert_eq!(
            caroot_of(TargetOs::Windows, env(no_caroot)),
            Some(Path::new(r"C:\Users\a\AppData\Local").join("mkcert"))
        );
        // `XDG_DATA_HOME` comes before the macOS default, as in mkcert.
        assert_eq!(
            caroot_of(TargetOs::MacOs, env(no_caroot)),
            Some(Path::new("/xdg").join("mkcert"))
        );
        let home = [("HOME", "/home/a"), ("XDG_DATA_HOME", ""), ("CAROOT", "")];
        assert_eq!(
            caroot_of(TargetOs::MacOs, env(&home)),
            Some(Path::new("/home/a/Library/Application Support").join("mkcert"))
        );
        assert_eq!(
            caroot_of(TargetOs::Linux, env(&home)),
            Some(Path::new("/home/a/.local/share").join("mkcert"))
        );
        assert_eq!(caroot_of(TargetOs::Windows, env(&home)), None);
    }

    #[test]
    fn a_consent_withdrawn_during_a_renewal_wins() {
        let now = time::macros::datetime!(2026-10-27 10:00 UTC);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "mkcert test");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = now - Duration::days(365);
        params.not_after = now + Duration::days(9 * 365);
        let ca = params.self_signed(&key).unwrap();
        let caroot = tempfile::tempdir().unwrap();
        fs::write(caroot.path().join(ROOT_CERT), ca.pem()).unwrap();
        fs::write(caroot.path().join(ROOT_KEY), key.serialize_pem()).unwrap();
        let data = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: data.path().join("tls"),
        };
        crate::save(&files, &issue_with_mkcert(caroot.path(), now).unwrap()).unwrap();

        // The withdrawal comes while the renewal has issued but not saved yet. Without the
        // lock it would finish during the pause and then be overwritten by the save.
        let late = now + Duration::days(780);
        let mut withdrawal = None;
        let renewed = renew_while_locked(&files, late, || {
            let files = files.clone();
            withdrawal = Some(std::thread::spawn(move || {
                crate::set_mkcert_consent(&files, None).unwrap()
            }));
            std::thread::sleep(std::time::Duration::from_millis(300));
        })
        .unwrap();
        assert!(withdrawal.unwrap().join().unwrap());
        let MkcertRenewal::Renewed(new) = renewed else {
            panic!("not renewed");
        };
        let info = crate::load_info(&files).unwrap().unwrap();
        assert_eq!(info.leaf_sha256, new.leaf_sha256);
        assert!(!info.source.renews_itself(), "{:?}", info.source);
        // Withdrawn: the next check renews nothing and reads no key.
        fs::write(caroot.path().join(ROOT_KEY), "not a key").unwrap();
        assert_eq!(
            renew_with_mkcert(&files, late).unwrap(),
            MkcertRenewal::NotDue
        );
    }
}
