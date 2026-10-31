//! `genKeyPairAndGetPKCS10(storageName, container, newDefaultPassword, String[] aliases,
//! String[] algs, int[] keyLengths, oidStr, valueList, subjectAlternativeNames)`, as the
//! applet's own `KeyStoreUtil` does it for file storages:
//!
//! - the subject is built from `oidStr` and `valueList` (`<:>`-separated, by position): the
//!   attributes CN, SURNAME, SERIALNUMBER, C, L, S, O, OU, G, BusinessCategory, E, DC and
//!   UID in the page's order, others dropped; each value without line feeds, trimmed and
//!   upper-cased. None is `GENKEY_EMPTY_DN`; an SERIALNUMBER other than `IIN` + 12
//!   characters, an OU starting with `BIN` that is not 15 characters, or a C other than
//!   `KZ` is `GENKEY_INCORRECT_DN_VALUE`;
//! - one key per `keyLengths` entry, of the algorithm `algs[i]`: GOST 34.310-2004
//!   (`1.2.398.3.10.1.1.1.2`) or sha256WithRSA (`1.2.840.113549.1.1.11`, `keyLengths[i]`
//!   bits). Anything else is `GENKEY_UNKNOWN_ALG`, which the original also answers for
//!   GOST 2015; unlike the original, sha1WithRSA, the GammaTech GOST and RSA lengths other
//!   than 2048, 3072 and 4096 too;
//! - the core generates each key and writes it alone into `<container>/<PREFIX><keyId>.p12`
//!   encrypted with `newDefaultPassword`; `aliases` are for ID cards only;
//! - the key identifier is the applet's: SHA-1 of the whole DER `SubjectPublicKeyInfo`
//!   (Kalkan's `getKeyIdFromPK`), not the BIT STRING hash of `generateCsr`; it is the alias,
//!   `localKeyId`, file name, SubjectKeyIdentifier and `secondResult`;
//! - the request has SubjectKeyIdentifier and, for a non-empty `subjectAlternativeNames`
//!   (`,`-separated), SubjectAltName dNSNames led by the CN; PEM `NEW CERTIFICATE REQUEST`
//!   with `\n` line ends;
//! - `result` is the requests, `secondResult` the key identifiers, each separated by
//!   `<:>`. A failure ends it; key files written before stay;
//! - unlike the original, more than [`MAX_KEYS_PER_REQUEST`] `keyLengths` entries are
//!   `GENKEY_COMMON` before any key is generated.
//!
//! The container must be an existing local folder given by an absolute path, or a network
//! folder the user chose in the file chooser (else `COMMON`, as a file the original cannot
//! write; the core refuses another network path before it is looked up); `JKS` is not
//! written (`UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION`). Tokens answer `EMPTY_SLOT`, and
//! `GENKEY_COMMON` when one of the family is connected: OpenNCALayer does not generate keys
//! on tokens.

use crate::Core;
use crate::dispatch::{Args, NPE, Outcome, Thrown, Wrapper};
use crate::methods::{
    COMMON, EMPTY_SLOT, JKS, UNKNOWN_STORAGE, UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION, is_token,
    java_split, keystore_cause, storage, token_connected,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pdk::abi::{Folder, NewKeyArgs, Password, RequestForm, cause};

const GENKEY_UNKNOWN_ALG: &str = "GENKEY_UNKNOWN_ALG";
const GENKEY_EMPTY_DN: &str = "GENKEY_EMPTY_DN";
const GENKEY_INCORRECT_DN_VALUE: &str = "GENKEY_INCORRECT_DN_VALUE";
const GENKEY_COMMON: &str = "GENKEY_COMMON";

/// `<:>`: the original's separator of subject parts, requests and key identifiers.
const SEPARATOR: &str = "<:>";

/// The most keys a request generates (the original has no limit): file storages generate
/// them without a window.
const MAX_KEYS_PER_REQUEST: usize = 16;

/// The subject attributes the applet's `KeyStoreUtil` takes, by OID (its `mapRDNs`).
const RDN_OIDS: [&str; 13] = [
    "2.5.4.3",
    "2.5.4.4",
    "2.5.4.5",
    "2.5.4.6",
    "2.5.4.7",
    "2.5.4.8",
    "2.5.4.10",
    "2.5.4.11",
    "2.5.4.42",
    "2.5.4.15",
    "1.2.840.113549.1.9.1",
    "0.9.2342.19200300.100.1.25",
    "0.9.2342.19200300.100.1.1",
];
const CN: &str = "2.5.4.3";
const SERIAL_NUMBER: &str = "2.5.4.5";
const COUNTRY: &str = "2.5.4.6";
const ORGANIZATIONAL_UNIT: &str = "2.5.4.11";

const GOST_2004: &str = "1.2.398.3.10.1.1.1.2";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
/// The RSA lengths the core generates.
const RSA_BITS: [u32; 3] = [2048, 3072, 4096];

/// Why generation stops early.
enum Stop {
    /// An `AppletException` with this code: the reply.
    Code(&'static str),
    /// An exception the method does not catch.
    Thrown(Thrown),
}

impl From<Thrown> for Stop {
    fn from(t: Thrown) -> Self {
        Stop::Thrown(t)
    }
}

/// `genKeyPairAndGetPKCS10`.
pub(crate) fn gen_key_pair_and_get_pkcs10<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    match generate_all(core, args) {
        Ok(wrapper) => Ok(wrapper),
        Err(Stop::Code(code)) => Ok(Wrapper::error(code)),
        Err(Stop::Thrown(thrown)) => Err(thrown),
    }
}

fn generate_all(core: &impl Core, args: &Args<'_>) -> Result<Wrapper, Stop> {
    let Some(storage) = storage(args.str(0)) else {
        return Err(Stop::Code(UNKNOWN_STORAGE));
    };
    if is_token(storage) {
        if token_connected(core, storage) {
            core.info(&format!(
                "Applet: generating keys is not supported for tokens ({storage})"
            ));
            return Err(Stop::Code(GENKEY_COMMON));
        }
        return Err(Stop::Code(EMPTY_SLOT));
    }
    let password = args.str(2).unwrap_or_default();

    let dn = subject(args.str(6), args.str(7))?;
    validate_subject(&dn)?;
    let csr_dn: Vec<(String, String)> = dn
        .iter()
        .map(|(oid, value)| {
            // Kalkan reads `#…` as DER and drops a leading `\`: the original escapes `#`,
            // so the value stays a string.
            let value = if value.starts_with('#') {
                format!("\\{value}")
            } else {
                value.clone()
            };
            ((*oid).to_owned(), value)
        })
        .collect();

    let lengths = args.ints(5).ok_or(NPE)?;
    // Unlike the original, a request may generate at most `MAX_KEYS_PER_REQUEST` keys: file
    // storages generate them without a window.
    if lengths.len() > MAX_KEYS_PER_REQUEST {
        return Err(Stop::Code(GENKEY_COMMON));
    }
    let mut requests = Vec::with_capacity(lengths.len());
    let mut key_ids = Vec::with_capacity(lengths.len());
    for (i, &length) in lengths.iter().enumerate() {
        let alg = *args
            .strs(4)
            .ok_or(NPE)?
            .get(i)
            .ok_or(Thrown("java.lang.ArrayIndexOutOfBoundsException"))?;
        if !java_oid_valid(alg) {
            return Err(Thrown("java.lang.IllegalArgumentException").into());
        }
        let bits = key_spec(alg, length).ok_or(Stop::Code(GENKEY_UNKNOWN_ALG))?;
        if storage == JKS {
            return Err(Stop::Code(UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION));
        }
        // The original's NullPointerException inside its generic `catch`.
        let container = args.str(1).ok_or(Stop::Code(GENKEY_COMMON))?;
        let dns_names = match args.str(8).filter(|s| !s.is_empty()) {
            Some(names) => Some(alt_names(names, &dn)?),
            None => None,
        };
        let made = core.new_key(NewKeyArgs {
            folder: Folder::Page(container.to_owned()),
            password: Password::Text(password.to_owned()),
            alg: alg.to_owned(),
            bits,
            form: RequestForm::Applet {
                dn: csr_dn.clone(),
                dns_names,
            },
        });
        let made =
            made.map_err(|e| Stop::Code(new_key_code(keystore_cause(&e, "keystore_new_key"))))?;
        requests.push(request_pem(&made.der));
        key_ids.push(made.key_id);
    }
    core.info(&format!(
        "genKeyPairAndGetPKCS10: key files created: {}",
        requests.len()
    ));
    if requests.is_empty() {
        return Ok(Wrapper::none());
    }
    Ok(Wrapper {
        second_result: Some(key_ids.join(SEPARATOR).into()),
        ..Wrapper::ok(requests.join(SEPARATOR))
    })
}

/// The original's code for a failure of `keystore_new_key` with `cause`: a folder that is
/// none (or one a page may not name) and a key file that is not written are `COMMON`, a key
/// that is not generated `GENKEY_UNKNOWN_ALG`, a request that is not built `GENKEY_COMMON`.
fn new_key_code(cause: &str) -> &'static str {
    let step = |s: &str| {
        cause
            .strip_prefix(s)
            .is_some_and(|rest| rest.starts_with('.'))
    };
    if step(cause::KEYSTORE_GENERATE) {
        GENKEY_UNKNOWN_ALG
    } else if step(cause::CSR) {
        GENKEY_COMMON
    } else {
        COMMON
    }
}

/// `genSubjectDN`: the known attributes of `oid_str` with the value at the same position
/// of `value_str`, without line feeds, trimmed and upper-cased (Kalkan's `X509Name` reads
/// the escaped values back as they were).
fn subject(
    oid_str: Option<&str>,
    value_str: Option<&str>,
) -> Result<Vec<(&'static str, String)>, Stop> {
    let oids = java_split(oid_str.ok_or(NPE)?, SEPARATOR);
    let values = java_split(value_str.ok_or(NPE)?, SEPARATOR);
    let mut dn = Vec::new();
    for (i, oid) in oids.into_iter().enumerate() {
        let Some(&oid) = RDN_OIDS.iter().find(|&&known| known == oid) else {
            continue;
        };
        let value = values
            .get(i)
            .ok_or(Thrown("java.lang.ArrayIndexOutOfBoundsException"))?;
        let value = java_trim(&value.replace('\n', "")).to_uppercase();
        dn.push((oid, value));
    }
    if dn.is_empty() {
        return Err(Stop::Code(GENKEY_EMPTY_DN));
    }
    Ok(dn)
}

/// `validateSubjectDN`: the first SERIALNUMBER is `IIN` and 12 more characters, every OU
/// starting with `BIN` has 15 characters, the first C is `KZ`.
fn validate_subject(dn: &[(&str, String)]) -> Result<(), Stop> {
    let first = |oid: &str| dn.iter().find(|(o, _)| *o == oid).map(|(_, v)| v.as_str());
    let java_len = |s: &str| s.encode_utf16().count();
    let iin_ok = first(SERIAL_NUMBER).is_none_or(|v| v.starts_with("IIN") && java_len(v) == 15);
    let bins_ok = dn
        .iter()
        .filter(|(o, v)| *o == ORGANIZATIONAL_UNIT && v.starts_with("BIN"))
        .all(|(_, v)| java_len(v) == 15);
    let country_ok = first(COUNTRY).is_none_or(|v| v == "KZ");
    if iin_ok && bins_ok && country_ok {
        Ok(())
    } else {
        Err(Stop::Code(GENKEY_INCORRECT_DN_VALUE))
    }
}

/// `getSubjectAlternativeNameArray`: the trimmed `,`-separated names, led by the subject's
/// CN unless one of them is it (ignoring case). Without a CN the original fails inside its
/// generic `catch`.
fn alt_names(names: &str, dn: &[(&str, String)]) -> Result<Vec<String>, Stop> {
    let cn = dn
        .iter()
        .find(|(oid, _)| *oid == CN)
        .map(|(_, v)| v.as_str())
        .ok_or(Stop::Code(GENKEY_COMMON))?;
    let mut names: Vec<String> = java_split(names, ",")
        .into_iter()
        .map(|n| java_trim(n).to_owned())
        .collect();
    if !names.iter().any(|n| java_equals_ignore_case(n, cn)) {
        names.insert(0, cn.to_owned());
    }
    Ok(names)
}

/// The key of `algs[i]`: GOST 2004 (no length), or sha256WithRSA of `length` bits (the
/// RSA length); `None` for another algorithm or length.
fn key_spec(alg: &str, length: i32) -> Option<Option<u32>> {
    match alg {
        GOST_2004 => Some(None),
        SHA256_WITH_RSA => {
            let bits = u32::try_from(length).ok()?;
            RSA_BITS.contains(&bits).then_some(Some(bits))
        }
        _ => None,
    }
}

/// `formatPKCS10`: base64 in lines of 64 between the `NEW CERTIFICATE REQUEST` lines, each
/// line ended by `\n` but the last.
fn request_pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 80);
    pem.push_str("-----BEGIN NEW CERTIFICATE REQUEST-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END NEW CERTIFICATE REQUEST-----");
    pem
}

/// Kalkan's `DERObjectIdentifier` check: `0.`, `1.` or `2.` then digit runs separated by
/// single dots, ending in a digit.
fn java_oid_valid(oid: &str) -> bool {
    let b = oid.as_bytes();
    if b.len() < 3 || b[1] != b'.' || !(b'0'..=b'2').contains(&b[0]) {
        return false;
    }
    let mut period_allowed = false;
    for &c in b[2..].iter().rev() {
        match c {
            b'0'..=b'9' => period_allowed = true,
            b'.' if period_allowed => period_allowed = false,
            _ => return false,
        }
    }
    period_allowed
}

/// Java's `String.trim`: every character up to U+0020 off both ends.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c| c <= ' ')
}

/// Java's `String.equalsIgnoreCase` for characters with single-character case mappings.
fn java_equals_ignore_case(a: &str, b: &str) -> bool {
    fn single(mut it: impl Iterator<Item = char>, c: char) -> char {
        match (it.next(), it.next()) {
            (Some(m), None) => m,
            _ => c,
        }
    }
    let upper = |c: char| single(c.to_uppercase(), c);
    let lower = |c: char| single(c.to_lowercase(), c);
    a.chars().count() == b.chars().count()
        && a.chars()
            .zip(b.chars())
            .all(|(x, y)| x == y || upper(x) == upper(y) || lower(upper(x)) == lower(upper(y)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dn(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        pairs.iter().map(|(o, v)| (*o, (*v).to_owned())).collect()
    }

    fn code(r: Result<impl std::fmt::Debug, Stop>) -> &'static str {
        match r {
            Err(Stop::Code(c)) => c,
            Err(Stop::Thrown(Thrown(t))) => t,
            Ok(v) => panic!("succeeded: {v:?}"),
        }
    }

    #[test]
    fn subjects() {
        let got = subject(
            Some("2.5.4.3<:>9.9<:>2.5.4.5<:>2.5.4.6"),
            Some(" Тестов\n Тест <:>x<:>iin123456789012<:>kz"),
        )
        .ok()
        .unwrap();
        assert_eq!(
            got,
            dn(&[
                (CN, "ТЕСТОВ ТЕСТ"),
                (SERIAL_NUMBER, "IIN123456789012"),
                (COUNTRY, "KZ")
            ])
        );
        assert_eq!(code(subject(Some("9.9"), Some("x"))), GENKEY_EMPTY_DN);
        assert_eq!(code(subject(Some(""), Some(""))), GENKEY_EMPTY_DN);
        // Trailing empty values are dropped by `split`: the CN has no value.
        assert_eq!(
            code(subject(Some("2.5.4.6<:>2.5.4.3"), Some("KZ<:>"))),
            "java.lang.ArrayIndexOutOfBoundsException"
        );
        assert_eq!(code(subject(None, Some("x"))), NPE.0);
        assert_eq!(code(subject(Some("2.5.4.3"), None)), NPE.0);
    }

    #[test]
    fn subject_checks() {
        let ok = |pairs: &[(&'static str, &str)]| validate_subject(&dn(pairs)).is_ok();
        assert!(ok(&[(CN, "A")]));
        assert!(ok(&[(SERIAL_NUMBER, "IIN123456789012"), (COUNTRY, "KZ")]));
        assert!(!ok(&[(SERIAL_NUMBER, "IIN12345678901")]));
        assert!(!ok(&[(SERIAL_NUMBER, "BIN123456789012")]));
        // Only the first SERIALNUMBER and C are checked.
        assert!(ok(&[
            (SERIAL_NUMBER, "IIN123456789012"),
            (SERIAL_NUMBER, "X")
        ]));
        assert!(!ok(&[(COUNTRY, "RU"), (COUNTRY, "KZ")]));
        assert!(ok(&[
            (ORGANIZATIONAL_UNIT, "BIN123456789012"),
            (ORGANIZATIONAL_UNIT, "X")
        ]));
        assert!(!ok(&[
            (ORGANIZATIONAL_UNIT, "X"),
            (ORGANIZATIONAL_UNIT, "BIN1")
        ]));
    }

    #[test]
    fn alternative_names() {
        let subject = dn(&[(CN, "HOST.KZ")]);
        assert_eq!(
            alt_names("a.kz, b.kz", &subject).ok().unwrap(),
            ["HOST.KZ", "a.kz", "b.kz"]
        );
        assert_eq!(
            alt_names("a.kz,host.kz,", &subject).ok().unwrap(),
            ["a.kz", "host.kz"]
        );
        assert_eq!(
            code(alt_names("a.kz", &dn(&[(COUNTRY, "KZ")]))),
            GENKEY_COMMON
        );
    }

    #[test]
    fn key_specs() {
        assert_eq!(key_spec(GOST_2004, 0), Some(None));
        assert_eq!(key_spec(SHA256_WITH_RSA, 2048), Some(Some(2048)));
        assert_eq!(key_spec(SHA256_WITH_RSA, 4096), Some(Some(4096)));
        assert_eq!(key_spec(SHA256_WITH_RSA, 1024), None);
        assert_eq!(key_spec(SHA256_WITH_RSA, -1), None);
        for refused in [
            "1.2.398.3.10.1.1.2.3.2",
            "1.2.840.113549.1.1.5",
            "1.3.6.1.4.1.6801.1.2.2",
            "1.2.840.113549.1.1.011",
        ] {
            assert_eq!(key_spec(refused, 2048), None, "{refused}");
        }
    }

    #[test]
    fn new_key_codes() {
        assert_eq!(new_key_code(cause::KEYSTORE_FOLDER_REFUSED), COMMON);
        assert_eq!(new_key_code(cause::KEYSTORE_FOLDER_MISSING), COMMON);
        assert_eq!(
            new_key_code("keystore.generate.unknown_algorithm"),
            GENKEY_UNKNOWN_ALG
        );
        assert_eq!(new_key_code("csr.invalid_request"), GENKEY_COMMON);
        assert_eq!(new_key_code("keystore.write.io"), COMMON);
    }

    #[test]
    fn oids() {
        assert!(java_oid_valid("1.2"));
        assert!(java_oid_valid("1.2.840.113549.1.1.011"));
        assert!(!java_oid_valid("1."));
        assert!(!java_oid_valid("3.1"));
        assert!(!java_oid_valid("1.2..3"));
        assert!(!java_oid_valid("1.2.3."));
        assert!(!java_oid_valid("1.a"));
        assert!(!java_oid_valid("12.3"));
    }

    #[test]
    fn pem_layout() {
        assert_eq!(
            request_pem(&[0xfb, 0xff]),
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n+/8=\n-----END NEW CERTIFICATE REQUEST-----"
        );
        let line = "A".repeat(64);
        assert_eq!(
            request_pem(&[0; 48]),
            format!(
                "-----BEGIN NEW CERTIFICATE REQUEST-----\n{line}\n-----END NEW CERTIFICATE REQUEST-----"
            )
        );
    }

    #[test]
    fn ignore_case() {
        assert!(java_equals_ignore_case("ТЕСТ", "тест"));
        assert!(java_equals_ignore_case("Host.KZ", "host.kz"));
        assert!(!java_equals_ignore_case("a", "ab"));
        assert!(!java_equals_ignore_case("a", "b"));
    }
}
