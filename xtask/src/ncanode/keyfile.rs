//! Our key files in Kalkan. For GOST 2015, GOST 2004 and RSA a key is generated, its
//! request built and checked here (NCANode has no PKCS#10 endpoint, and `/x509/verify`
//! takes the signed data as UTF-8 text, which a request is not), and the key written alone
//! into `<PREFIX><keyId>.p12` (`oncl_pki::keystore`). NCANode must list the key under its
//! key identifier. A synthetic key of the same algorithm then issues a certificate on the
//! request; it is installed into the key file and the password changed, as `importCertificate`
//! does. NCANode must find the certificate in the file, and Kalkan must sign CMS with the
//! file's key, which NCANode then verifies.

use super::{CHAIN_INCOMPLETE, CONTENT, Expect, Ncanode, Row, Signer};
use anyhow::{Context, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::OctetString;
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use oncl_pki::csr::{CsrRequest, KeyStoreInfo, build_csr};
use oncl_pki::key::PublicKey;
use oncl_pki::keygen::{KeySpec, generate, key_id};
use oncl_pki::keystore::{change_password, create_key_file, install_certificate};
use oncl_pki::oid;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use serde_json::{Value, json};
use std::fs;
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::request::{CertReq, ExtensionReq};

/// Password of a new key file (the page's `defaultPassword`).
const DEFAULT_PASSWORD: &str = "Default1";
/// Password after the certificate is installed (the user's).
const PASSWORD: &str = "Interop12";

/// The checks; `issuers` are the synthetic GOST 2015, GOST 2004 and RSA signers.
pub(super) fn check(node: &Ncanode, issuers: &[Signer]) -> anyhow::Result<Vec<Row>> {
    let [gost2015, gost2004, rsa] = issuers else {
        anyhow::bail!("expected the 3 synthetic keys");
    };
    let target = oncl_testkit::workspace_root().join("target");
    fs::create_dir_all(&target)?;
    let mut rows = Vec::new();
    for (spec, label, issuer) in [
        (KeySpec::Gost2015_512, "generated GOST 2015", gost2015),
        (KeySpec::Gost2004, "generated GOST 2004", gost2004),
        (KeySpec::RsaSha256(2048), "generated RSA", rsa),
    ] {
        let dir = tempfile::Builder::new()
            .prefix("oncl-ncanode-keys-")
            .tempdir_in(&target)?;
        let key = generate(spec)?;
        let pem = build_csr(
            &key,
            spec,
            &CsrRequest {
                dn: &[
                    (oid::COMMON_NAME, "OpenNCALayer interop".to_owned()),
                    (oid::SERIAL_NUMBER, "IIN000000000000".to_owned()),
                    (oid::COUNTRY, "KZ".to_owned()),
                ],
                dns_names: &[],
                email: None,
                keystore_info: KeyStoreInfo {
                    storage_oid: oid::STORAGE_PKCS12,
                    path: Some(dir.path().display().to_string()),
                },
            },
        )?;
        let request = verified_request(&pem, spec).with_context(|| format!("{label}: CSR"))?;
        let path = create_key_file(dir.path(), &key, spec, DEFAULT_PASSWORD)?;
        let alias = key_id(&key.public_key());
        rows.push(node.aliases(
            "our key file: key alone",
            label,
            &fs::read(&path)?,
            DEFAULT_PASSWORD,
            &alias,
        ));

        let serial = serial(&alias);
        let cert = issue(issuer, &request, &serial)?;
        let path = install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12)?;
        change_password(&path, DEFAULT_PASSWORD, PASSWORD)?;
        let p12 = fs::read(&path)?;
        rows.push(node.pkcs12_info(
            "our key file: certificate installed",
            label,
            &p12,
            &serial_hex(&serial),
        ));
        rows.push(node.kalkan_cms("our key file: Kalkan signs CMS", label, &p12));
    }
    Ok(rows)
}

/// The request in `pem`, checked: its signature verifies with the key it carries.
fn verified_request(pem: &str, spec: KeySpec) -> anyhow::Result<CertReq> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let req = CertReq::from_der(&STANDARD.decode(body)?)?;
    ensure!(req.algorithm.oid == spec.sig_alg().signature_oid());
    let public = PublicKey::from_spki(&req.info.public_key)?;
    let signature = req.signature.as_bytes().context("signature BIT STRING")?;
    public.verify(spec.sig_alg(), &req.info.to_der()?, signature)?;
    Ok(req)
}

/// A serial number from the key identifier, positive and without a leading zero.
fn serial(alias: &str) -> Vec<u8> {
    let mut serial: Vec<u8> = (0..16)
        .step_by(2)
        .map(|i| u8::from_str_radix(&alias[i..i + 2], 16).expect("hex key identifier"))
        .collect();
    serial[0] = 0x40 | (serial[0] & 0x3f);
    serial
}

/// The serial as NCANode prints it (`BigInteger.toString(16)`).
fn serial_hex(serial: &[u8]) -> String {
    serial.iter().map(|b| format!("{b:02x}")).collect()
}

/// A signing certificate on `request` from `issuer`, as the NCA issues one: the request's
/// subject, key and extensions (KeyStoreInfo), SubjectKeyIdentifier = the key identifier,
/// digitalSignature + nonRepudiation.
fn issue(issuer: &Signer, request: &CertReq, serial: &[u8]) -> anyhow::Result<Certificate> {
    let ski = SubjectKeyIdentifier(OctetString::new(hex_decode(&key_id(
        &PublicKey::from_spki(&request.info.public_key)?,
    )))?);
    let mut extensions = vec![
        extension(SubjectKeyIdentifier::OID, &ski)?,
        extension(
            KeyUsage::OID,
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
        )?,
    ];
    for attribute in request.info.attributes.iter() {
        for value in attribute.values.iter() {
            extensions.extend(ExtensionReq::from_der(&value.to_der()?)?.0);
        }
    }
    Ok(issue_cert(
        &issuer.entry,
        TestCertSpec {
            subject: request.info.subject.clone(),
            public_key: request.info.public_key.clone(),
            serial: serial.to_vec(),
            validity: *issuer.entry.cert.tbs_certificate().validity(),
            extensions,
        },
    ))
}

fn extension(
    extn_id: der::asn1::ObjectIdentifier,
    value: &impl Encode,
) -> anyhow::Result<Extension> {
    Ok(Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex key identifier"))
        .collect()
}

/// A row that passes when `found` (NCANode's answer) equals `expected`.
fn compare_row(check: &str, key: &str, found: &str, expected: &str) -> Row {
    let pass = found == expected;
    Row {
        check: check.to_owned(),
        key: key.to_owned(),
        signature: if pass { "opened" } else { "UNEXPECTED" }.to_owned(),
        valid: "-".to_owned(),
        detail: if pass {
            found.to_owned()
        } else {
            format!("{found}; expected {expected}")
        },
        pass,
    }
}

/// `/pkcs12/aliases` response: the aliases of the one key store.
fn aliases(response: &Value) -> String {
    response["aliases"].to_string()
}

/// `/pkcs12/info` response: the serial of each certificate found.
fn serials(response: &Value) -> String {
    response["signers"]
        .as_array()
        .map(|signers| {
            signers
                .iter()
                .map(|s| s["serialNumber"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

impl Ncanode {
    fn signer_request(p12: &[u8], password: &str) -> Value {
        json!({ "key": STANDARD.encode(p12), "password": password })
    }

    /// Kalkan opens the key file and lists `alias`, the key identifier, alone.
    fn aliases(&self, check: &str, key: &str, p12: &[u8], password: &str, alias: &str) -> Row {
        let body = json!({ "keys": [Self::signer_request(p12, password)] });
        match self.post("/pkcs12/aliases", &body) {
            Ok(response) => compare_row(
                check,
                key,
                &aliases(&response),
                &json!([[alias]]).to_string(),
            ),
            Err(e) => Row::failed(check, key, &e),
        }
    }

    /// Kalkan finds the certificate of the key file's key: one certificate, `serial`.
    fn pkcs12_info(&self, check: &str, key: &str, p12: &[u8], serial: &str) -> Row {
        let body = json!({ "keys": [Self::signer_request(p12, PASSWORD)] });
        match self.post("/pkcs12/info", &body) {
            Ok(response) => compare_row(check, key, &serials(&response), serial),
            Err(e) => Row::failed(check, key, &e),
        }
    }

    /// Kalkan signs CMS with the key file's key; NCANode verifies the result.
    fn kalkan_cms(&self, check: &str, key: &str, p12: &[u8]) -> Row {
        let body = json!({
            "data": STANDARD.encode(CONTENT),
            "signers": [Self::signer_request(p12, PASSWORD)],
            "withTsp": false,
            "detached": false,
        });
        let cms = self.post("/cms/sign", &body).and_then(|response| {
            let cms = response["cms"]
                .as_str()
                .context("/cms/sign returned no cms")?;
            Ok(STANDARD.decode(cms)?)
        });
        match cms {
            Ok(cms) => self.verify_cms(
                check,
                key,
                &cms,
                None,
                1,
                Expect::Accepted(CHAIN_INCOMPLETE),
            ),
            Err(e) => Row::failed(check, key, &e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_compare_to_the_expected_values() {
        let response = json!({ "status": 200, "aliases": [["ab12"]] });
        let row = compare_row(
            "c",
            "k",
            &aliases(&response),
            &json!([["ab12"]]).to_string(),
        );
        assert!(row.pass);
        assert_eq!(row.signature, "opened");
        let row = compare_row(
            "c",
            "k",
            &aliases(&response),
            &json!([["cd34"]]).to_string(),
        );
        assert!(!row.pass);
        assert_eq!(row.signature, "UNEXPECTED");

        let info = json!({ "valid": false, "signers": [{ "serialNumber": "4f01" }] });
        assert_eq!(serials(&info), "4f01");
        assert_eq!(serials(&json!({})), "");
    }

    #[test]
    fn serial_is_positive_without_leading_zero() {
        let serial = serial("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff");
        assert_eq!(serial.len(), 8);
        assert_eq!(serial[0] & 0xc0, 0x40);
        assert_eq!(serial_hex(&serial), "40ff00ff00ff00ff");
    }
}
