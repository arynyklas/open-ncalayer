//! `cargo xtask fetch-fixtures`: downloads NCANode test fixtures from a pinned
//! commit, verifies their sha256, extracts the PKCS#12 test keys embedded in
//! `WithTestData.groovy` and the Kalkan-signed XML documents embedded in
//! `XmlServiceTest.groovy`. Nothing here is committed: files land in
//! `target/fixtures/ncanode/`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// Pinned NCANode commit the fixtures are taken from.
pub const NCANODE_COMMIT: &str = "0adab29a7d30c181d70e8cc6b4f243122f50c3b8";

const NCANODE_RAW_BASE: &str = "https://raw.githubusercontent.com/ncanode-kz/NCANode";

/// File downloaded verbatim from the NCANode repository.
struct RemoteFile {
    path: &'static str,
    sha256: &'static str,
}

/// PKCS#12 key stored as a base64 constant in `WithTestData.groovy`.
struct GroovyKey {
    constant: &'static str,
    file: &'static str,
    sha256: &'static str,
}

/// XML document stored as a triple-quoted constant in `XmlServiceTest.groovy`, written
/// without the surrounding whitespace.
struct GroovyXml {
    constant: &'static str,
    file: &'static str,
    sha256: &'static str,
}

const GROOVY_FILE: &str = "WithTestData.groovy";
const GROOVY_XML_FILE: &str = "XmlServiceTest.groovy";

const REMOTE_FILES: &[RemoteFile] = &[
    RemoteFile {
        path: "src/test/groovy/kz/ncanode/common/WithTestData.groovy",
        sha256: "010bfffbaaabd960f205bfa5c9948bdaa4a8d87f6556e7f6521fd9667d0eaf33",
    },
    RemoteFile {
        path: "src/test/resources/cades/cades-test.bin",
        sha256: "d0b53c0368a842be1ab3f96715d22f87dafd19d2363c72cfddb0f2d514c682b1",
    },
    RemoteFile {
        path: "src/test/resources/cades/cades-test-signed-b.p7s",
        sha256: "0a4aad87a2fa53f37f28ee506ac6cd647670395b91af0afa24e6e7cb1d40cee8",
    },
    RemoteFile {
        path: "src/test/resources/tsp/tsp_response.bin",
        sha256: "0ad2f5f88e3f7f2753cb87a038da4a55884b3f7c8f1320a6d0dcced45f9946f6",
    },
    RemoteFile {
        path: "src/test/resources/tsp/tsp_token.bin",
        sha256: "976f0037123e4886757f357f0620e387c902b41b35f9ca8c25a378aa38ac3d5b",
    },
    RemoteFile {
        path: "src/test/resources/certs/ceo_valid_sign_2004_gost.cer",
        sha256: "820f1e97670210618331ce52e5a77060106f8b438ede4e09577ad457c520c0ac",
    },
    RemoteFile {
        path: "src/test/resources/certs/individual_valid_sign_2004_rsa.cer",
        sha256: "4ae454f541b8c83dd20f2ee87136a2a87b083594931e6056da61ab1157e393d9",
    },
    // XAdES-B/T/LT/LTA (GOST 2015, exclusive canonicalization, a SignedProperties reference).
    RemoteFile {
        path: "src/test/resources/xades/xades-test-signed-b.xml",
        sha256: "1b02674345ce641a655a2f0e74ad3a27c50766cc2d6e650867f54e0d7ecdcc65",
    },
    RemoteFile {
        path: "src/test/resources/xades/xades-test-signed-t.xml",
        sha256: "9915a1e5e0b50b4583c63f6b29786869eaec53bf518baea78c0dda19dbd67793",
    },
    RemoteFile {
        path: "src/test/resources/xades/xades-test-signed-lt.xml",
        sha256: "72fe233be85e8a4f632056995195765143e40ca40d5c6d6c577892a57e3f1660",
    },
    RemoteFile {
        path: "src/test/resources/xades/xades-test-signed-lta.xml",
        sha256: "01a75067d5644a91387bff15507bf471424d5349a753667c2e15c551c97ff86e",
    },
    RemoteFile {
        path: "src/test/groovy/kz/ncanode/unit/service/XmlServiceTest.groovy",
        sha256: "b17ec71014bb95eb05a51eab44cd33668020156edec011d055f995744a0c4371",
    },
];

/// The test keys. Despite its name, `KEY_INDIVIDUAL_VALID_SIGN_2004` is an RSA-2048 key
/// (issuer `ҰКО 3.0 (RSA TEST)`); `KEY_CEO_SIGN_REVOKED_2004` is the GOST 34.310-2004 one.
const GROOVY_KEYS: &[GroovyKey] = &[
    GroovyKey {
        constant: "KEY_INDIVIDUAL_VALID_SIGN_2004",
        file: "individual_valid_sign_2004.p12",
        sha256: "32ebec53426729a94a580c975c22ae359e70c6dd9064094ef743ec0b2ff2dbd4",
    },
    GroovyKey {
        constant: "KEY_INDIVIDUAL_VALID_2015",
        file: "individual_valid_2015.p12",
        sha256: "7b3c8cea6659f737e35a3a5b452b98f417449366cd16c26adb225da22131dfda",
    },
    GroovyKey {
        constant: "KEY_CEO_SIGN_REVOKED_2004",
        file: "ceo_sign_revoked_2004.p12",
        sha256: "f969f9b173cceed1ce596b9225e45eb4bb5dae1be75d541e500017dc7094d3e5",
    },
];

/// Enveloped XMLDSig documents signed by Kalkan in the original NCALayer shape.
const GROOVY_XMLS: &[GroovyXml] = &[
    GroovyXml {
        constant: "XML_SIGNED_VALID_STRING",
        file: "xmldsig-signed-rsa.xml",
        sha256: "8cabfb4e7984b3a4a87119facc3086c9a9a9e36cf3bee6cf4f6d365e313a8c87",
    },
    GroovyXml {
        constant: "XML_SIGNED_VALID_STRING_TWO_SIGNERS",
        file: "xmldsig-signed-rsa-gost2015.xml",
        sha256: "654213a73594eec41009278895b0cd564f72d08796aad977f27ae774e3a73a43",
    },
];

/// Directory the NCANode fixtures are stored in.
pub fn ncanode_dir() -> PathBuf {
    oncl_testkit::workspace_root().join("target/fixtures/ncanode")
}

/// Downloads the pinned NCANode fixtures and extracts the embedded test keys.
/// Files already present with the expected sha256 are left untouched.
pub fn fetch_fixtures() -> anyhow::Result<()> {
    let dir = ncanode_dir();
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;

    for remote in REMOTE_FILES {
        let name = remote.path.rsplit('/').next().unwrap_or(remote.path);
        let dest = dir.join(name);
        if is_current(&dest, remote.sha256)? {
            println!("up to date  {name}");
            continue;
        }
        let url = format!("{NCANODE_RAW_BASE}/{NCANODE_COMMIT}/{}", remote.path);
        let bytes = download(&url)?;
        verify_sha256(&bytes, remote.sha256).with_context(|| url.clone())?;
        write(&dest, &bytes)?;
        println!("fetched     {name}");
    }

    let groovy_path = dir.join(GROOVY_FILE);
    let groovy = fs::read_to_string(&groovy_path)
        .with_context(|| format!("cannot read {}", groovy_path.display()))?;
    for key in GROOVY_KEYS {
        let dest = dir.join(key.file);
        if is_current(&dest, key.sha256)? {
            println!("up to date  {}", key.file);
            continue;
        }
        let b64 = groovy_constant(&groovy, key.constant)
            .with_context(|| format!("constant {} not found in {GROOVY_FILE}", key.constant))?;
        let der = STANDARD
            .decode(b64)
            .with_context(|| format!("constant {} is not valid base64", key.constant))?;
        verify_sha256(&der, key.sha256).with_context(|| key.constant)?;
        write(&dest, &der)?;
        println!("extracted   {}", key.file);
    }

    let groovy_xml_path = dir.join(GROOVY_XML_FILE);
    let groovy_xml = fs::read_to_string(&groovy_xml_path)
        .with_context(|| format!("cannot read {}", groovy_xml_path.display()))?;
    for xml in GROOVY_XMLS {
        let dest = dir.join(xml.file);
        if is_current(&dest, xml.sha256)? {
            println!("up to date  {}", xml.file);
            continue;
        }
        let text = groovy_triple_quoted(&groovy_xml, xml.constant)
            .with_context(|| format!("constant {} not found in {GROOVY_XML_FILE}", xml.constant))?;
        let text = text.trim();
        verify_sha256(text.as_bytes(), xml.sha256).with_context(|| xml.constant)?;
        write(&dest, text.as_bytes())?;
        println!("extracted   {}", xml.file);
    }
    Ok(())
}

/// Returns the value of a Groovy constant declared as `NAME = '…'`.
pub fn groovy_constant(src: &str, name: &str) -> Option<String> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    src.match_indices(name).find_map(|(at, _)| {
        if src[..at].chars().next_back().is_some_and(is_ident) {
            return None;
        }
        let rest = src[at + name.len()..].trim_start().strip_prefix('=')?;
        let value = rest.trim_start().strip_prefix('\'')?;
        let end = value.find('\'')?;
        Some(value[..end].to_owned())
    })
}

/// Returns the value of a Groovy constant declared as `NAME = """…"""` (no interpolation).
pub fn groovy_triple_quoted<'s>(src: &'s str, name: &str) -> Option<&'s str> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    src.match_indices(name).find_map(|(at, _)| {
        if src[..at].chars().next_back().is_some_and(is_ident) {
            return None;
        }
        let rest = src[at + name.len()..].trim_start().strip_prefix('=')?;
        let value = rest.trim_start().strip_prefix("\"\"\"")?;
        let end = value.find("\"\"\"")?;
        Some(&value[..end])
    })
}

/// Checks that `bytes` hash to `expected_hex` (case-insensitive hex sha256).
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> anyhow::Result<()> {
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected_hex) {
        bail!("sha256 mismatch: expected {expected_hex}, got {actual}");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `true` if `path` exists and its sha256 matches; a stale file is re-fetched.
fn is_current(path: &Path, expected_hex: &str) -> anyhow::Result<bool> {
    match fs::read(path) {
        Ok(bytes) => Ok(verify_sha256(&bytes, expected_hex).is_ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// The largest body [`download`] reads: the NCANode fixtures and the site generator's
/// archive.
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;

/// The body of `url`, at most [`MAX_DOWNLOAD`] bytes.
pub(crate) fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .with_context(|| format!("reading body of {url}"))
}

fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    fs::write(path, bytes).with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_quoted_groovy_constant() {
        let src = "final static String KEY_A = 'QUJD'\nfinal static String KEY_B = 'x'";
        assert_eq!(groovy_constant(src, "KEY_A").unwrap(), "QUJD");
        assert!(groovy_constant(src, "KEY_C").is_none());
    }

    #[test]
    fn rejects_sha256_mismatch() {
        let err = verify_sha256(b"abc", "00".repeat(32).as_str()).unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn accepts_matching_sha256() {
        verify_sha256(
            b"abc",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        )
        .unwrap();
    }

    #[test]
    fn groovy_constant_matches_whole_name_only() {
        let src = "String KEY_A_PASSWORD = 'pw'\nString XKEY_A = 'no'\nString KEY_A = 'yes'";
        assert_eq!(groovy_constant(src, "KEY_A").unwrap(), "yes");
    }

    #[test]
    fn extracts_triple_quoted_groovy_constant() {
        let src = "String XML_A = \"\"\"\n<a/>\n\"\"\"\nString XML_A_B = \"\"\"<b/>\"\"\"";
        assert_eq!(groovy_triple_quoted(src, "XML_A").unwrap(), "\n<a/>\n");
        assert_eq!(groovy_triple_quoted(src, "XML_A_B").unwrap(), "<b/>");
        assert!(groovy_triple_quoted(src, "XML_C").is_none());
    }
}
