//! `cargo xtask gen-fixtures [--check]`: the synthetic NCA-like PKI in `fixtures/synthetic/`.
//!
//! Three self-signed roots (GOST 2015-512, GOST 34.310-2004, RSA-2048) issue PKCS#12 key
//! stores in the Kalkan profile: alias = hex(SKI), user subjects with IIN/BIN, NCA key usages,
//! extended key usages and policies. For certificate validation, `root-gost2015` also issues
//! an intermediate CA (and a same-subject twin with another key); the intermediate issues user
//! keys that point to an OCSP responder and a CRL, and the OCSP responders themselves. The
//! keys of the intermediate and of `root-gost2015` are stored too, for tests that sign CRLs.
//! All randomness comes from one [`ChaCha20Rng`] with a fixed seed, so the files are
//! reproducible and `--check` regenerates them in memory and compares. New objects are drawn
//! after all earlier ones, so adding them leaves the earlier files byte for byte unchanged.
//! `fixtures.toml` describes the containers for `oncl_testkit::synthetic`.

mod issue;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use der::DateTime;
use der::Encode;
use der::asn1::{GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString};
use issue::{CertSpec, Issuer, Key, KeyKind, extension, issue};
use oncl_gost::GostAlg;
use oncl_pki::pkcs12::{self, Pbe, WriteEntry, WriteOptions};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, BasicConstraints, CertificatePolicies,
    CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, KeyUsages,
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
const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
/// NCA RK: individual.
const EKU_NCA_INDIVIDUAL: &str = "1.2.398.3.3.4.1.1";
/// NCA RK: legal entity, first head.
const EKU_NCA_LEGAL_HEAD: &str = "1.2.398.3.3.4.1.2.1";

// Certificate policies.
const POLICY_SIGN: &str = "1.2.398.3.3.2.3";
const POLICY_AUTH: &str = "1.2.398.3.3.2.4";

/// id-ad-ocsp: the OCSP access method of AuthorityInfoAccess.
const AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
/// id-pkix-ocsp-nocheck: the responder's own certificate is not checked for revocation.
const OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

// Revocation sources of the intermediate PKI (`.test` names never resolve).
const OCSP_URL: &str = "http://ocsp.synthetic.test";
const ROOT_CRL_URL: &str = "http://crl.synthetic.test/root-gost2015.crl";
const INTER_CRL_URL: &str = "http://crl.synthetic.test/inter-gost2015.crl";

/// Intermediate CA under `root-gost2015` and its twin (same subject, other key): `.cer` names
/// without extension.
const INTER: &str = "inter-gost2015";
const INTER_TWIN: &str = "inter-gost2015-twin";
/// Common name of the intermediate CA and of its twin.
const INTER_CN: &str = "SYNTHETIC NCA (GOST) 2015";

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
    /// OCSP responder: EKU OCSPSigning and id-pkix-ocsp-nocheck.
    Ocsp,
    /// OCSP responder without id-pkix-ocsp-nocheck.
    OcspNoCheckless,
}

/// Who the certificate is issued to.
enum Subject {
    Individual,
    Legal,
    Tsa,
    Ocsp,
}

impl Profile {
    fn subject(self) -> Subject {
        match self {
            Profile::Sign | Profile::Auth | Profile::LegacyAuth => Subject::Individual,
            Profile::LegalSign => Subject::Legal,
            Profile::Tsa => Subject::Tsa,
            Profile::Ocsp | Profile::OcspNoCheckless => Subject::Ocsp,
        }
    }

    /// Whether this is an OCSP responder, whose own status is not published.
    fn ocsp_responder(self) -> bool {
        matches!(self, Profile::Ocsp | Profile::OcspNoCheckless)
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
            Profile::Ocsp | Profile::OcspNoCheckless => (
                KeyUsages::DigitalSignature.into(),
                &[EKU_OCSP_SIGNING][..],
                false,
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
        if self == Profile::Ocsp {
            extensions.push(Extension {
                extn_id: oid(OCSP_NOCHECK),
                critical: false,
                extn_value: OctetString::new(Null.to_der().expect("NULL")).expect("extnValue"),
            });
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
    /// 2025-01-01T00:00:00Z … 2026-01-01T00:00:00Z: expired, but inside the validity of the
    /// CAs (which start with [`Period::Normal`]), so the chain builds at its `notAfter`.
    ExpiredUnderCa,
}

impl Period {
    fn validity(self) -> Validity {
        let (from, to) = match self {
            Period::Normal => ((2025, 1, 1, 0, 0, 0), (2099, 12, 31, 23, 59, 59)),
            Period::Expired => ((2020, 1, 1, 0, 0, 0), (2021, 1, 1, 0, 0, 0)),
            Period::ExpiredUnderCa => ((2025, 1, 1, 0, 0, 0), (2026, 1, 1, 0, 0, 0)),
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
    /// Root the entries chain to; their key type is the root's.
    root: Root,
    /// One entry per profile, in this order.
    profiles: &'static [Profile],
    period: Period,
    encryption: Encryption,
    /// Whether the entries carry AuthorityKeyIdentifier.
    authority_key_id: bool,
}

/// A container valid for the normal period, in the Kalkan profile, with
/// AuthorityKeyIdentifier.
const fn container(name: &'static str, root: Root, profiles: &'static [Profile]) -> Container {
    Container {
        name,
        root,
        profiles,
        period: Period::Normal,
        encryption: Encryption::Kalkan,
        authority_key_id: true,
    }
}

/// Containers issued directly by their root.
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

/// Containers issued by the intermediate CA [`INTER`] (all under `root-gost2015`, so their
/// `root` is [`Root::Gost2015`]). Entries other than OCSP responders point to [`OCSP_URL`]
/// and [`INTER_CRL_URL`]; `inter-revoked-…` is the one the tests report as revoked.
const INTER_CONTAINERS: &[Container] = &[
    container("inter-user-gost2015-sign", Root::Gost2015, &[Profile::Sign]),
    container(
        "inter-revoked-gost2015-sign",
        Root::Gost2015,
        &[Profile::Sign],
    ),
    Container {
        period: Period::ExpiredUnderCa,
        ..container(
            "inter-expired-gost2015-sign",
            Root::Gost2015,
            &[Profile::Sign],
        )
    },
    container("ocsp-gost2015", Root::Gost2015, &[Profile::Ocsp]),
    container(
        "ocsp-nocheckless-gost2015",
        Root::Gost2015,
        &[Profile::OcspNoCheckless],
    ),
];

/// Issued by [`INTER`] like `inter-user-…`, but without AuthorityKeyIdentifier: only the
/// signature tells [`INTER`] from its same-subject twin. Drawn after the CA key containers.
const INTER_NOAKI: Container = Container {
    authority_key_id: false,
    ..container(
        "inter-noaki-gost2015-sign",
        Root::Gost2015,
        &[Profile::Sign],
    )
};

/// A generated CA: its `.cer` name without extension, subject, key and certificate.
struct IssuedCa {
    file: &'static str,
    name: Name,
    key: Key,
    cert: Vec<u8>,
}

impl IssuedCa {
    fn issuer(&self) -> Issuer<'_> {
        Issuer {
            name: &self.name,
            key: &self.key,
        }
    }

    /// The CA's own key and certificate as a container entry.
    fn entry(&self) -> WriteEntry {
        WriteEntry {
            alias: hex(&self.key.ski),
            pkcs8_der: self.key.pkcs8_der.clone(),
            cert_der: Some(self.cert.clone()),
        }
    }
}

/// The generated files and the manifest describing the containers among them.
struct Output {
    files: BTreeMap<String, Vec<u8>>,
    manifest: String,
}

impl Output {
    fn add_cer(&mut self, ca: &IssuedCa) {
        self.files
            .insert(format!("{}.cer", ca.file), ca.cert.clone());
    }

    /// Writes the container `name` with `entries`, issued by `issuer` under `root`, and its
    /// manifest record.
    fn add_p12(
        &mut self,
        name: &str,
        root: &IssuedCa,
        issuer: &IssuedCa,
        entries: &[WriteEntry],
        encryption: Encryption,
        rng: &mut ChaCha20Rng,
    ) {
        let p12 = pkcs12::write(
            entries,
            &[],
            PASSWORD,
            &encryption.write_options(),
            &mut |buf| rng.fill_bytes(buf),
        )
        .expect("synthetic keys and certificates are valid");
        self.files.insert(format!("{name}.p12"), p12);

        let aliases: Vec<String> = entries.iter().map(|e| format!("\"{}\"", e.alias)).collect();
        write!(
            self.manifest,
            "\n[[p12]]\nname = \"{name}\"\npassword = \"{PASSWORD}\"\nroot = \"{}.cer\"\n\
             issuer = \"{}.cer\"\naliases = [{}]\n",
            root.file,
            issuer.file,
            aliases.join(", "),
        )
        .expect("writing to a String");
    }

    /// Writes `container`, issued by the intermediate `inter` under `root` with the
    /// revocation `pointers`.
    fn add_inter_p12(
        &mut self,
        container: &Container,
        root: &IssuedCa,
        inter: &IssuedCa,
        pointers: &[Extension],
        rng: &mut ChaCha20Rng,
    ) {
        assert_eq!(
            container.root,
            Root::Gost2015,
            "{}: the intermediate is under root-gost2015",
            container.name
        );
        let entries = issue_entries(container, inter, pointers, rng);
        self.add_p12(
            container.name,
            root,
            inter,
            &entries,
            container.encryption,
            rng,
        );
    }
}

/// Generates every file of `fixtures/synthetic/`: file name → contents.
pub fn generate() -> BTreeMap<String, Vec<u8>> {
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let mut out = Output {
        files: BTreeMap::new(),
        manifest: String::from(
            "# Generated by `cargo xtask gen-fixtures`: do not edit.\n\
             # Synthetic PKCS#12 containers for `oncl_testkit::synthetic`; aliases in load order.\n",
        ),
    };

    let roots: Vec<(Root, IssuedCa)> = Root::ALL
        .into_iter()
        .map(|root| (root, self_signed_root(root, &mut rng)))
        .collect();
    let root_ca = |root: Root| {
        &roots
            .iter()
            .find(|(r, _)| *r == root)
            .expect("every root is generated")
            .1
    };
    for (_, ca) in &roots {
        out.add_cer(ca);
    }
    for container in CONTAINERS {
        let root = root_ca(container.root);
        let entries = issue_entries(container, root, &[], &mut rng);
        out.add_p12(
            container.name,
            root,
            root,
            &entries,
            container.encryption,
            &mut rng,
        );
    }

    // The validation PKI is drawn after everything above, which therefore stays unchanged.
    let root = root_ca(Root::Gost2015);
    let inter = intermediate(INTER, root, &mut rng);
    let twin = intermediate(INTER_TWIN, root, &mut rng);
    out.add_cer(&inter);
    out.add_cer(&twin);
    let pointers = [ocsp_access(OCSP_URL), crl_distribution_point(INTER_CRL_URL)];
    for container in INTER_CONTAINERS {
        out.add_inter_p12(container, root, &inter, &pointers, &mut rng);
    }
    for ca in [&inter, root] {
        out.add_p12(
            &format!("{}.key", ca.file),
            root,
            root,
            &[ca.entry()],
            Encryption::Kalkan,
            &mut rng,
        );
    }
    out.add_inter_p12(&INTER_NOAKI, root, &inter, &pointers, &mut rng);

    out.files
        .insert(MANIFEST.to_owned(), out.manifest.into_bytes());
    out.files
}

/// The self-signed `root`: `cA` without a path length, keyCertSign and cRLSign.
fn self_signed_root(root: Root, rng: &mut ChaCha20Rng) -> IssuedCa {
    let key = Key::generate(root.key_kind(), rng);
    let name = name(&[
        (CN, root.common_name()),
        (ORGANIZATION, "OpenNCALayer"),
        (COUNTRY, "KZ"),
    ]);
    let spec = CertSpec {
        subject: name.clone(),
        validity: Period::Normal.validity(),
        serial: serial(rng, false),
        extensions: ca_extensions(None),
        authority_key_id: false,
    };
    let cert = issue(spec, &key, None, rng);
    IssuedCa {
        file: root.name(),
        name,
        key,
        cert,
    }
}

/// A GOST 2015-512 intermediate CA `file` issued by `root`: subject [`INTER_CN`], `cA` with
/// path length 0, keyCertSign and cRLSign, the root's CRL at [`ROOT_CRL_URL`]. Each call
/// draws a new key and serial number under the same subject.
fn intermediate(file: &'static str, root: &IssuedCa, rng: &mut ChaCha20Rng) -> IssuedCa {
    let key = Key::generate(KeyKind::Gost(GostAlg::Gost3410_2015_512), rng);
    let name = name(&[(CN, INTER_CN), (COUNTRY, "KZ")]);
    let mut extensions = ca_extensions(Some(0));
    extensions.push(crl_distribution_point(ROOT_CRL_URL));
    let spec = CertSpec {
        subject: name.clone(),
        validity: Period::Normal.validity(),
        serial: serial(rng, false),
        extensions,
        authority_key_id: true,
    };
    let cert = issue(spec, &key, Some(root.issuer()), rng);
    IssuedCa {
        file,
        name,
        key,
        cert,
    }
}

/// Critical basicConstraints (`cA`, `path_len`) and keyUsage keyCertSign + cRLSign.
fn ca_extensions(path_len: Option<u8>) -> Vec<Extension> {
    vec![
        extension(
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: path_len,
            },
        ),
        extension(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
    ]
}

/// One entry per profile of `container`, issued by `ca`. `pointers` (revocation sources)
/// follow the profile's extensions, except in OCSP responders.
fn issue_entries(
    container: &Container,
    ca: &IssuedCa,
    pointers: &[Extension],
    rng: &mut ChaCha20Rng,
) -> Vec<WriteEntry> {
    container
        .profiles
        .iter()
        .map(|&profile| {
            let key = Key::generate(container.root.key_kind(), rng);
            let mut extensions = profile.extensions();
            if !profile.ocsp_responder() {
                extensions.extend_from_slice(pointers);
            }
            let spec = CertSpec {
                subject: subject(profile.subject()),
                validity: container.period.validity(),
                serial: serial(rng, profile == Profile::LegalSign),
                extensions,
                authority_key_id: container.authority_key_id,
            };
            let cert_der = issue(spec, &key, Some(ca.issuer()), rng);
            WriteEntry {
                alias: hex(&key.ski),
                pkcs8_der: key.pkcs8_der.clone(),
                cert_der: Some(cert_der),
            }
        })
        .collect()
}

/// AuthorityInfoAccess with the OCSP responder at `url`.
fn ocsp_access(url: &str) -> Extension {
    extension(
        false,
        &AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: oid(AD_OCSP),
            access_location: uri(url),
        }]),
    )
}

/// CRLDistributionPoints with one `fullName` URI.
fn crl_distribution_point(url: &str) -> Extension {
    extension(
        false,
        &CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![uri(url)])),
            reasons: None,
            crl_issuer: None,
        }]),
    )
}

fn uri(url: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(Ia5String::new(url).expect("ASCII URL"))
}

/// Regenerates `fixtures/synthetic/` under the workspace `root`, removing generated-kind
/// files (see [`existing_files`]) that are no longer generated.
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

/// Names of the files in `dir` that `gen-fixtures` owns: `*.p12`, `*.cer` and the manifest.
/// Anything else (OS or editor files, notes, directories) is not ours and is ignored. An
/// absent directory has none.
fn existing_files(dir: &Path) -> anyhow::Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path: PathBuf = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let generated_kind = name == MANIFEST
            || Path::new(name)
                .extension()
                .is_some_and(|e| e == "p12" || e == "cer");
        if generated_kind && path.is_file() {
            names.push(name.to_owned());
        }
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
        Subject::Ocsp => name(&[(CN, "OpenNCALayer Synthetic OCSP"), (COUNTRY, "KZ")]),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_files_are_left_alone() {
        let root = std::env::temp_dir().join(format!("oncl-gen-fixtures-{}", std::process::id()));
        let dir = root.join(DIR);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(dir.join("scratch")).unwrap();
        for junk in [".DS_Store", "notes.txt", "user-gost2015-sign.p12.swp"] {
            fs::write(dir.join(junk), b"junk").unwrap();
        }
        fs::write(dir.join("retired.p12"), b"stale").unwrap();
        fs::write(dir.join("retired.cer"), b"stale").unwrap();

        gen_fixtures(&root).unwrap();
        assert!(check(&root).unwrap(), "foreign files make the check fail");
        for junk in [".DS_Store", "notes.txt", "user-gost2015-sign.p12.swp"] {
            assert_eq!(fs::read(dir.join(junk)).unwrap(), b"junk", "{junk}");
        }
        assert!(dir.join("scratch").is_dir());
        assert!(!dir.join("retired.p12").exists());
        assert!(!dir.join("retired.cer").exists());

        fs::write(dir.join("retired.cer"), b"stale").unwrap();
        assert!(!check(&root).unwrap(), "a stale certificate is reported");
        fs::remove_dir_all(&root).unwrap();
    }
}
