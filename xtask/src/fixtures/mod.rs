//! `cargo xtask gen-fixtures [--check]`: the synthetic NCA-like PKI in `fixtures/synthetic/`.
//!
//! Three self-signed roots (GOST 2015-512, GOST 34.310-2004, RSA-2048) issue PKCS#12 key
//! stores in the Kalkan profile: alias = hex(SKI), user subjects with IIN/BIN, NCA key usages,
//! extended key usages and policies. All randomness comes from one [`ChaCha20Rng`] with a fixed
//! seed, so the files are reproducible and `--check` regenerates them in memory and compares.
//! `fixtures.toml` describes the containers for `oncl_testkit::synthetic`.

mod issue;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, bail};
use der::DateTime;
use der::asn1::{GeneralizedTime, ObjectIdentifier};
use issue::{CertSpec, Issuer, Key, KeyKind, extension, issue};
use oncl_gost::GostAlg;
use oncl_pki::pkcs12::{self, Pbe, WriteEntry, WriteOptions};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::{
    BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, KeyUsages,
};
use x509_cert::name::Name;
use x509_cert::time::{Time, Validity};

/// Seed of the one RNG behind every random value of the synthetic PKI.
const SEED: [u8; 32] = *b"openncalayer-synthetic-pki-v1\0\0\0";

/// Password of every container.
const PASSWORD: &str = "Qwerty12";

/// Directory of the generated files, relative to the workspace root.
const DIR: &str = "fixtures/synthetic";

/// File describing the containers for `oncl_testkit`.
const MANIFEST: &str = "fixtures.toml";

/// Serial number length in bytes.
const SERIAL_LEN: usize = 16;

// Extended key usages.
const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// NCA RK: individual.
const EKU_NCA_INDIVIDUAL: &str = "1.2.398.3.3.4.1.1";
/// NCA RK: legal entity, first head.
const EKU_NCA_LEGAL_HEAD: &str = "1.2.398.3.3.4.1.2.1";

// Certificate policies.
const POLICY_SIGN: &str = "1.2.398.3.3.2.3";
const POLICY_AUTH: &str = "1.2.398.3.3.2.4";

// Name attributes (dotted OIDs: `x509-cert` picks PrintableString for C and SERIALNUMBER,
// UTF8String for the rest).
const CN: &str = "2.5.4.3";
const SURNAME: &str = "2.5.4.4";
const SERIAL_NUMBER: &str = "2.5.4.5";
const COUNTRY: &str = "2.5.4.6";
const ORGANIZATION: &str = "2.5.4.10";
const ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
const GIVEN_NAME: &str = "2.5.4.42";

/// A self-signed root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Root {
    Gost2015,
    Gost2004,
    Rsa,
}

impl Root {
    const ALL: [Root; 3] = [Root::Gost2015, Root::Gost2004, Root::Rsa];

    /// Name of the `.cer` file without extension.
    fn name(self) -> &'static str {
        match self {
            Root::Gost2015 => "root-gost2015",
            Root::Gost2004 => "root-gost2004",
            Root::Rsa => "root-rsa",
        }
    }

    fn common_name(self) -> &'static str {
        match self {
            Root::Gost2015 => "OpenNCALayer Synthetic Root GOST 2015",
            Root::Gost2004 => "OpenNCALayer Synthetic Root GOST 2004",
            Root::Rsa => "OpenNCALayer Synthetic Root RSA",
        }
    }

    /// Key type of the root and of the keys it issues.
    fn key_kind(self) -> KeyKind {
        match self {
            Root::Gost2015 => KeyKind::Gost(GostAlg::Gost3410_2015_512),
            Root::Gost2004 => KeyKind::Gost(GostAlg::Gost34310_2004),
            Root::Rsa => KeyKind::Rsa,
        }
    }
}

/// Certificate profile of a container entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    /// Individual, signing.
    Sign,
    /// Individual, authentication.
    Auth,
    /// Individual, authentication without the clientAuth EKU (older NCA certificates).
    LegacyAuth,
    /// Legal entity head, signing; the serial number has its top bit set.
    LegalSign,
    /// Time-stamping authority.
    Tsa,
}

/// Who the certificate is issued to.
enum Subject {
    Individual,
    Legal,
    Tsa,
}

impl Profile {
    fn subject(self) -> Subject {
        match self {
            Profile::Sign | Profile::Auth | Profile::LegacyAuth => Subject::Individual,
            Profile::LegalSign => Subject::Legal,
            Profile::Tsa => Subject::Tsa,
        }
    }

    fn extensions(self) -> Vec<Extension> {
        let signing = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
        let auth = KeyUsages::DigitalSignature | KeyUsages::KeyAgreement;
        let (key_usage, eku, eku_critical, policy) = match self {
            Profile::Sign => (
                signing,
                &[EKU_EMAIL_PROTECTION, EKU_NCA_INDIVIDUAL][..],
                false,
                Some(POLICY_SIGN),
            ),
            Profile::Auth => (
                auth,
                &[EKU_CLIENT_AUTH, EKU_NCA_INDIVIDUAL][..],
                false,
                Some(POLICY_AUTH),
            ),
            Profile::LegacyAuth => (auth, &[EKU_NCA_INDIVIDUAL][..], false, Some(POLICY_AUTH)),
            Profile::LegalSign => (
                signing,
                &[EKU_EMAIL_PROTECTION, EKU_NCA_LEGAL_HEAD][..],
                false,
                Some(POLICY_SIGN),
            ),
            Profile::Tsa => (
                KeyUsages::DigitalSignature.into(),
                &[EKU_TIME_STAMPING][..],
                true,
                None,
            ),
        };
        let mut extensions = vec![
            extension(true, &KeyUsage(key_usage)),
            extension(
                eku_critical,
                &ExtendedKeyUsage(eku.iter().map(|o| oid(o)).collect()),
            ),
        ];
        if let Some(policy) = policy {
            extensions.push(extension(
                false,
                &CertificatePolicies(vec![PolicyInformation {
                    policy_identifier: oid(policy),
                    policy_qualifiers: None,
                }]),
            ));
        }
        extensions
    }
}

/// Validity period of a container's certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Period {
    /// 2025-01-01T00:00:00Z … 2099-12-31T23:59:59Z.
    Normal,
    /// 2020-01-01T00:00:00Z … 2021-01-01T00:00:00Z.
    Expired,
}

impl Period {
    fn validity(self) -> Validity {
        let (from, to) = match self {
            Period::Normal => ((2025, 1, 1, 0, 0, 0), (2099, 12, 31, 23, 59, 59)),
            Period::Expired => ((2020, 1, 1, 0, 0, 0), (2021, 1, 1, 0, 0, 0)),
        };
        Validity::new(time(from), time(to))
    }
}

/// Encryption of a container's keys and certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encryption {
    /// The Kalkan profile: 3DES keys, RC2-40 certificates.
    Kalkan,
    /// Keys and certificates under PBES2 without a PRF field (AES-256-CBC).
    Pbes2NoPrf,
}

impl Encryption {
    fn write_options(self) -> WriteOptions {
        match self {
            Encryption::Kalkan => WriteOptions::default(),
            Encryption::Pbes2NoPrf => WriteOptions {
                key: Pbe::Pbes2Aes256NoPrf,
                certs: Pbe::Pbes2Aes256NoPrf,
                ..WriteOptions::default()
            },
        }
    }
}

/// A PKCS#12 container of the synthetic PKI. Every container gets its own keys.
struct Container {
    /// File name without `.p12`.
    name: &'static str,
    root: Root,
    /// One entry per profile, in this order.
    profiles: &'static [Profile],
    period: Period,
    encryption: Encryption,
}

/// A container valid for the normal period, in the Kalkan profile.
const fn container(name: &'static str, root: Root, profiles: &'static [Profile]) -> Container {
    Container {
        name,
        root,
        profiles,
        period: Period::Normal,
        encryption: Encryption::Kalkan,
    }
}

const CONTAINERS: &[Container] = &[
    container("user-gost2015-sign", Root::Gost2015, &[Profile::Sign]),
    container("user-gost2015-auth", Root::Gost2015, &[Profile::Auth]),
    container(
        "legacy-gost2015-auth",
        Root::Gost2015,
        &[Profile::LegacyAuth],
    ),
    container("user-gost2004-sign", Root::Gost2004, &[Profile::Sign]),
    container("user-rsa-sign", Root::Rsa, &[Profile::Sign]),
    container("legal-gost2015-sign", Root::Gost2015, &[Profile::LegalSign]),
    Container {
        period: Period::Expired,
        ..container("expired-gost2015-sign", Root::Gost2015, &[Profile::Sign])
    },
    container(
        "multi-gost2015",
        Root::Gost2015,
        &[Profile::Sign, Profile::Auth],
    ),
    container("tsa-gost2015", Root::Gost2015, &[Profile::Tsa]),
    Container {
        encryption: Encryption::Pbes2NoPrf,
        ..container("pbes2-noprf-gost2015", Root::Gost2015, &[Profile::Sign])
    },
];

/// A generated root: its kind, name and key.
struct IssuedRoot {
    root: Root,
    name: Name,
    key: Key,
}

/// Generates every file of `fixtures/synthetic/`: file name → contents.
pub fn generate() -> BTreeMap<String, Vec<u8>> {
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let mut files = BTreeMap::new();

    let mut roots = Vec::new();
    for root in Root::ALL {
        let key = Key::generate(root.key_kind(), &mut rng);
        let name = name(&[
            (CN, root.common_name()),
            (ORGANIZATION, "OpenNCALayer"),
            (COUNTRY, "KZ"),
        ]);
        let spec = CertSpec {
            subject: name.clone(),
            validity: Period::Normal.validity(),
            serial: serial(&mut rng, false),
            extensions: vec![
                extension(
                    true,
                    &BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    },
                ),
                extension(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
            ],
        };
        let cert = issue(spec, &key, None, &mut rng);
        files.insert(format!("{}.cer", root.name()), cert);
        roots.push(IssuedRoot { root, name, key });
    }

    let mut manifest = String::from(
        "# Generated by `cargo xtask gen-fixtures`: do not edit.\n\
         # Synthetic PKCS#12 containers for `oncl_testkit::synthetic`; aliases in load order.\n",
    );
    for container in CONTAINERS {
        let root = roots
            .iter()
            .find(|r| r.root == container.root)
            .expect("every root is generated");
        let issuer = Issuer {
            name: &root.name,
            key: &root.key,
        };
        let entries: Vec<WriteEntry> = container
            .profiles
            .iter()
            .map(|&profile| {
                let key = Key::generate(container.root.key_kind(), &mut rng);
                let spec = CertSpec {
                    subject: subject(profile.subject()),
                    validity: container.period.validity(),
                    serial: serial(&mut rng, profile == Profile::LegalSign),
                    extensions: profile.extensions(),
                };
                let cert_der = issue(spec, &key, Some(issuer), &mut rng);
                WriteEntry {
                    alias: hex(&key.ski),
                    pkcs8_der: key.pkcs8_der.clone(),
                    cert_der,
                }
            })
            .collect();
        let p12 = pkcs12::write(
            &entries,
            PASSWORD,
            &container.encryption.write_options(),
            &mut |buf| rng.fill_bytes(buf),
        );
        files.insert(format!("{}.p12", container.name), p12);

        let aliases: Vec<String> = entries.iter().map(|e| format!("\"{}\"", e.alias)).collect();
        write!(
            manifest,
            "\n[[p12]]\nname = \"{}\"\npassword = \"{PASSWORD}\"\nroot = \"{}.cer\"\naliases = [{}]\n",
            container.name,
            container.root.name(),
            aliases.join(", "),
        )
        .expect("writing to a String");
    }
    files.insert(MANIFEST.to_owned(), manifest.into_bytes());
    files
}

/// Regenerates `fixtures/synthetic/` under the workspace `root`, removing files that are no
/// longer generated.
///
/// # Errors
///
/// If the directory cannot be read or written.
pub fn gen_fixtures(root: &Path) -> anyhow::Result<()> {
    let dir = root.join(DIR);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let files = generate();
    for stale in existing_files(&dir)?
        .into_iter()
        .filter(|f| !files.contains_key(f))
    {
        let path = dir.join(stale);
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    for (name, contents) in &files {
        let path = dir.join(name);
        fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
    }
    println!("wrote {} files to {}", files.len(), dir.display());
    Ok(())
}

/// Whether `fixtures/synthetic/` under the workspace `root` holds exactly the files
/// [`generate`] produces. Differences are reported on stderr.
///
/// # Errors
///
/// If the directory cannot be read.
pub fn check(root: &Path) -> anyhow::Result<bool> {
    let dir = root.join(DIR);
    let files = generate();
    let existing = existing_files(&dir)?;
    let mut fresh = true;
    for name in existing.iter().filter(|f| !files.contains_key(*f)) {
        eprintln!("{DIR}/{name}: not generated by gen-fixtures");
        fresh = false;
    }
    for (name, contents) in &files {
        let path = dir.join(name);
        if !existing.contains(name) {
            eprintln!("{DIR}/{name}: missing");
            fresh = false;
        } else if fs::read(&path).with_context(|| format!("reading {}", path.display()))?
            != *contents
        {
            eprintln!("{DIR}/{name}: differs from the generated file");
            fresh = false;
        }
    }
    Ok(fresh)
}

/// File names in `dir`; an absent directory has none.
fn existing_files(dir: &Path) -> anyhow::Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path: PathBuf = entry?.path();
        if !path.is_file() {
            bail!("unexpected non-file {} in {DIR}", path.display());
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("non-UTF-8 file name {}", path.display()))?;
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Subject name of an entry; attributes in DER order.
fn subject(subject: Subject) -> Name {
    match subject {
        Subject::Individual => name(&[
            (CN, "ТЕСТОВ ТЕСТ"),
            (SURNAME, "ТЕСТОВ"),
            (GIVEN_NAME, "ТЕСТОВИЧ"),
            (SERIAL_NUMBER, "IIN123456789011"),
            (COUNTRY, "KZ"),
        ]),
        Subject::Legal => name(&[
            (CN, "ТЕСТОВА ДАНА"),
            (SURNAME, "ТЕСТОВА"),
            (GIVEN_NAME, "ТЕСТОВНА"),
            (SERIAL_NUMBER, "IIN123456789022"),
            (COUNTRY, "KZ"),
            (ORGANIZATION, "ТОО СИНТЕТИКА"),
            (ORGANIZATIONAL_UNIT, "BIN123456789021"),
        ]),
        Subject::Tsa => name(&[(CN, "OpenNCALayer Synthetic TSA"), (COUNTRY, "KZ")]),
    }
}

/// Name with one attribute per RDN, `attrs` in DER order (an RFC 4514 string lists them in
/// reverse).
fn name(attrs: &[(&str, &str)]) -> Name {
    let rfc4514: Vec<String> = attrs
        .iter()
        .rev()
        .map(|(oid, value)| format!("{oid}={value}"))
        .collect();
    Name::from_str(&rfc4514.join(",")).expect("valid name")
}

/// Serial number of [`SERIAL_LEN`] bytes from `rng`. The top bit of the first byte is set
/// when `top_bit` (the DER INTEGER then starts with `00`), else cleared with the next bit
/// set, so the INTEGER is always exactly as long as the drawn bytes.
fn serial(rng: &mut ChaCha20Rng, top_bit: bool) -> Vec<u8> {
    let mut serial = vec![0; SERIAL_LEN];
    rng.fill_bytes(&mut serial);
    serial[0] = if top_bit {
        serial[0] | 0x80
    } else {
        (serial[0] & 0x7f) | 0x40
    };
    serial
}

/// UTC time; `Validity` encodes it as UTCTime before 2050, GeneralizedTime from 2050.
fn time((year, month, day, hour, minute, second): (u16, u8, u8, u8, u8, u8)) -> Time {
    let date = DateTime::new(year, month, day, hour, minute, second).expect("valid date");
    Time::GeneralTime(GeneralizedTime::from_date_time(date))
}

fn oid(dotted: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(dotted).expect("valid OID")
}

/// Lowercase hex, as Kalkan writes aliases.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
