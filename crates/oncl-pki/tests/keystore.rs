//! Kalkan-shaped key files: a new key alone in `<PREFIX><keyId>.p12`, its certificate
//! installed later (found by SubjectKeyIdentifier in the directory), password changes.

use oncl_pki::cert::Certificate;
use oncl_pki::csr::KeyStoreInfo;
use oncl_pki::key::{PrivateKey, PublicKey};
use oncl_pki::keygen::{KeySpec, applet_key_id, generate, key_id};
use oncl_pki::keystore::{
    KeystoreError, MAX_KEY_FILE, MAX_KEY_FILES, certificate_alias, change_password,
    change_password_data, check_password_pattern, create_applet_key_file, create_key_file,
    install_certificate, install_certificate_in_page_folder,
};
use oncl_pki::oid;
use oncl_pki::pkcs12::{
    self, KeyEntry, Pkcs12Error, WriteEntry, WriteOptions, load, load_contents,
};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{read, synthetic};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::TempDir;
use x509_cert::der::Encode;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::name::Name;

const DEFAULT_PASSWORD: &str = "Default1";
/// Storage OID of JKS key files.
const STORAGE_JKS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.5.1.2");

/// What the test CA puts into a certificate.
#[derive(Clone, Copy, Default)]
struct Profile {
    /// Authentication: digitalSignature + keyEncipherment + clientAuth; else signing:
    /// digitalSignature + nonRepudiation.
    auth: bool,
    /// Without SubjectKeyIdentifier.
    no_ski: bool,
    /// KeyStoreInfo storage.
    storage: Option<ObjectIdentifier>,
}

/// The synthetic key of `spec`'s algorithm, as the issuer of test certificates: the
/// certificate signature algorithm follows the key, as at the NCA.
fn issuer(spec: KeySpec) -> KeyEntry {
    let name = match spec {
        KeySpec::Gost2015_512 => "user-gost2015-sign",
        KeySpec::Gost2004 => "user-gost2004-sign",
        KeySpec::RsaSha256(_) | KeySpec::Rsa1Sha1(_) => "user-rsa-sign",
    };
    let fixture = synthetic(name);
    load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}

fn extension(extn_id: ObjectIdentifier, value: &impl Encode) -> Extension {
    Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// A certificate for `public` (of `spec`) under `ski_of`'s key identifier.
fn certificate_with_ski(
    spec: KeySpec,
    public: &PublicKey,
    ski_of: &PublicKey,
    profile: Profile,
) -> Certificate {
    let issuer = issuer(spec);
    let mut extensions = Vec::new();
    if !profile.no_ski {
        let ski = hex_decode(&key_id(ski_of));
        extensions.push(extension(
            SubjectKeyIdentifier::OID,
            &SubjectKeyIdentifier(OctetString::new(ski).unwrap()),
        ));
    }
    let usage = if profile.auth {
        KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment
    } else {
        KeyUsages::DigitalSignature | KeyUsages::NonRepudiation
    };
    extensions.push(extension(KeyUsage::OID, &KeyUsage(usage)));
    if profile.auth {
        extensions.push(extension(
            ExtendedKeyUsage::OID,
            &ExtendedKeyUsage(vec![oid::CLIENT_AUTH]),
        ));
    }
    if let Some(storage_oid) = profile.storage {
        let info = KeyStoreInfo {
            storage_oid,
            path: Some("C:\\keys".to_owned()),
        };
        extensions.push(Extension {
            extn_id: oid::KEYSTORE_INFO,
            critical: false,
            extn_value: OctetString::new(info.to_der().unwrap()).unwrap(),
        });
    }
    issue_cert(
        &issuer,
        TestCertSpec {
            subject: Name::from_str("CN=Test").unwrap(),
            public_key: public.to_spki(),
            serial: vec![0x42, 0x01],
            validity: *issuer.cert.tbs_certificate().validity(),
            extensions,
        },
    )
}

fn certificate(spec: KeySpec, key: &PrivateKey, profile: Profile) -> Certificate {
    let public = key.public_key();
    certificate_with_ski(spec, &public, &public, profile)
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// A key file of a new `spec` key in a new directory.
fn key_file(spec: KeySpec) -> (TempDir, PrivateKey, PathBuf) {
    let dir = TempDir::new().unwrap();
    let key = generate(spec).unwrap();
    let path = create_key_file(dir.path(), &key, spec, DEFAULT_PASSWORD).unwrap();
    (dir, key, path)
}

/// The key signs with the certificate's algorithm and the certificate's key verifies it.
fn assert_pair(entry: &KeyEntry, spec: KeySpec) {
    let public =
        PublicKey::from_spki(entry.cert.tbs_certificate().subject_public_key_info()).unwrap();
    let sig = entry.key.sign(spec.sig_alg(), b"pair").unwrap();
    public.verify(spec.sig_alg(), b"pair", &sig).unwrap();
}

#[test]
fn new_key_files_hold_the_key_alone() {
    for (spec, prefix) in [
        (KeySpec::Gost2015_512, "GOST512_"),
        (KeySpec::Gost2004, "GOSTKNCA_"),
        (KeySpec::RsaSha256(2048), "RSA256_"),
    ] {
        let (dir, key, path) = key_file(spec);
        let id = key_id(&key.public_key());
        assert_eq!(
            path,
            dir.path().join(format!("{prefix}{id}.p12")),
            "{spec:?}"
        );
        // Written atomically: no temporary file is left behind.
        assert_eq!(file_names(dir.path()), [format!("{prefix}{id}.p12")]);

        let p12 = fs::read(&path).unwrap();
        // The P1 reader skips keys without a certificate; `load_contents` keeps them.
        assert!(load(&p12, DEFAULT_PASSWORD).unwrap().is_empty());
        let contents = load_contents(&p12, DEFAULT_PASSWORD).unwrap();
        assert_eq!(contents.keys.len(), 1, "{spec:?}");
        let stored = &contents.keys[0];
        assert_eq!(stored.alias, id, "{spec:?}");
        assert!(stored.cert.is_none());
        assert_eq!(stored.key.public_key(), key.public_key(), "{spec:?}");
        assert!(contents.other_certs.is_empty());
        assert!(matches!(
            load_contents(&p12, "Wrong123"),
            Err(Pkcs12Error::WrongPassword)
        ));
    }
}

#[test]
fn key_file_prefix_for_sha1_rsa_and_mismatched_keys() {
    let dir = TempDir::new().unwrap();
    let rsa = issuer(KeySpec::RsaSha256(2048)).key;
    let path = create_key_file(dir.path(), &rsa, KeySpec::Rsa1Sha1(2048), "x").unwrap();
    let name = path.file_name().unwrap().to_str().unwrap();
    assert_eq!(name, format!("RSA_{}.p12", key_id(&rsa.public_key())));
    assert_eq!(
        create_key_file(dir.path(), &rsa, KeySpec::Gost2004, "x").unwrap_err(),
        KeystoreError::UnknownAlgorithm
    );
    let missing = dir.path().join("missing");
    let err = create_key_file(&missing, &rsa, KeySpec::RsaSha256(2048), "x").unwrap_err();
    assert!(matches!(err, KeystoreError::Io(_)), "{err:?}");
}

#[test]
fn installed_certificate_pairs_with_the_key() {
    for spec in [
        KeySpec::Gost2015_512,
        KeySpec::Gost2004,
        KeySpec::RsaSha256(2048),
    ] {
        let (dir, key, path) = key_file(spec);
        // Other files of the directory: another password, not PKCS#12, not a key file.
        let (_, other, _) = key_file(spec);
        create_key_file(dir.path(), &other, spec, "Another1").unwrap();
        fs::write(dir.path().join("broken.p12"), b"not a key store").unwrap();
        fs::write(dir.path().join("notes.txt"), b"x").unwrap();

        let cert = certificate(
            spec,
            &key,
            Profile {
                storage: Some(oid::STORAGE_PKCS12),
                ..Profile::default()
            },
        );
        let installed =
            install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
        assert_eq!(
            installed, path,
            "{spec:?}: a signing certificate keeps the name"
        );

        let entries = load(&fs::read(&path).unwrap(), DEFAULT_PASSWORD).unwrap();
        assert_eq!(entries.len(), 1, "{spec:?}");
        assert_eq!(entries[0].alias, key_id(&key.public_key()));
        assert_eq!(entries[0].cert, cert);
        assert_pair(&entries[0], spec);
        assert_eq!(
            file_names(dir.path()).len(),
            4,
            "{spec:?}: no temporary file left"
        );
    }
}

#[test]
fn install_into_the_file_itself() {
    let (_dir, key, path) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    let installed =
        install_certificate(&path, DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
    assert_eq!(installed, path);
    assert_eq!(
        load(&fs::read(&path).unwrap(), DEFAULT_PASSWORD)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn authentication_certificates_rename_the_file_unless_gost_2015() {
    let auth = Profile {
        auth: true,
        ..Profile::default()
    };
    let (dir, key, path) = key_file(KeySpec::RsaSha256(2048));
    let cert = certificate(KeySpec::RsaSha256(2048), &key, auth);
    let installed =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
    let name = path.file_name().unwrap().to_str().unwrap();
    assert_eq!(installed, dir.path().join(format!("AUTH_{name}")));
    assert!(!path.exists());
    let entries = load(&fs::read(&installed).unwrap(), DEFAULT_PASSWORD).unwrap();
    assert_pair(&entries[0], KeySpec::RsaSha256(2048));

    // Installing again into the renamed file keeps its name.
    let again =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
    assert_eq!(again, installed);

    // GOST 2015-512 keys are dual-use: no rename.
    let (dir, key, path) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, auth);
    let installed =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
    assert_eq!(installed, path);

    // GOST 2004 authentication certificates are renamed.
    let (dir, key, path) = key_file(KeySpec::Gost2004);
    let cert = certificate(KeySpec::Gost2004, &key, auth);
    let installed =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
    let name = path.file_name().unwrap().to_str().unwrap();
    assert_eq!(installed, dir.path().join(format!("AUTH_{name}")));
}

#[test]
fn unsuited_storage() {
    let (dir, key, _) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(
        KeySpec::Gost2015_512,
        &key,
        Profile {
            storage: Some(STORAGE_JKS),
            ..Profile::default()
        },
    );
    let err =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert_eq!(err, KeystoreError::UnsuitedStorage);
    assert_eq!(err.provider_code(), Some("UNSUITED_STORAGE"));

    // Without KeyStoreInfo any storage suits, but only PKCS#12 files are written.
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    let err = install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &STORAGE_JKS).unwrap_err();
    assert_eq!(err, KeystoreError::UnsupportedStorage);
    assert_eq!(
        err.provider_code(),
        Some("UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION")
    );
}

#[test]
fn inappropriate_certificate() {
    let (dir, key, path) = key_file(KeySpec::Gost2015_512);
    let before = fs::read(&path).unwrap();
    // The certificate names the key of the file but carries another key.
    let other = generate(KeySpec::Gost2015_512).unwrap().public_key();
    let cert = certificate_with_ski(
        KeySpec::Gost2015_512,
        &other,
        &key.public_key(),
        Profile::default(),
    );
    let err =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert_eq!(err, KeystoreError::InappropriateCert);
    assert_eq!(err.provider_code(), Some("INAPPROPRIATE_CERT"));
    assert_eq!(fs::read(&path).unwrap(), before, "the file is not touched");
}

#[test]
fn keystore_file_not_found() {
    let (dir, _, _) = key_file(KeySpec::Gost2015_512);
    let stranger = generate(KeySpec::Gost2015_512).unwrap();
    let cert = certificate(KeySpec::Gost2015_512, &stranger, Profile::default());
    let alias = key_id(&stranger.public_key());
    let err =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert_eq!(err.provider_code(), Some("KEYSTORE_FILE_NOT_FOUND"));
    assert_eq!(
        err.to_string(),
        format!(
            "По указанному пути \"{}\" отсутствует файл, предназначенный для хранения ключей с алиасом - {alias}.",
            dir.path().display()
        )
    );

    // The right file with the wrong password is skipped like any other.
    let (dir, key, _) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    let err = install_certificate(dir.path(), "Wrong123", &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert!(
        matches!(err, KeystoreError::KeystoreFileNotFound(_)),
        "{err:?}"
    );

    let missing = dir.path().join("missing");
    let err =
        install_certificate(&missing, DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert!(
        matches!(err, KeystoreError::KeystoreFileNotFound(_)),
        "{err:?}"
    );
}

#[test]
fn certificate_without_subject_key_identifier() {
    let (dir, key, _) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(
        KeySpec::Gost2015_512,
        &key,
        Profile {
            no_ski: true,
            ..Profile::default()
        },
    );
    let err =
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap_err();
    assert_eq!(err, KeystoreError::ExtensionNotFound);
    assert_eq!(err.provider_code(), Some("EXTENSION_NOT_FOUND"));
}

#[test]
fn certificate_alias_touches_no_file() {
    let key = generate(KeySpec::Gost2015_512).unwrap();
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    assert_eq!(
        certificate_alias(&cert, &oid::STORAGE_PKCS12),
        Ok(key_id(&key.public_key()))
    );
    let no_ski = certificate(
        KeySpec::Gost2015_512,
        &key,
        Profile {
            no_ski: true,
            ..Profile::default()
        },
    );
    assert_eq!(
        certificate_alias(&no_ski, &oid::STORAGE_PKCS12),
        Err(KeystoreError::ExtensionNotFound)
    );
    // Checked before any folder is looked at.
    let missing = Path::new("/no/such/folder");
    assert_eq!(
        install_certificate(missing, DEFAULT_PASSWORD, &no_ski, &oid::STORAGE_PKCS12),
        Err(KeystoreError::ExtensionNotFound)
    );
    assert_eq!(
        certificate_alias(&cert, &STORAGE_JKS),
        Err(KeystoreError::UnsupportedStorage)
    );
}

/// The legacy Applet names keys by SHA-1 of the whole SubjectPublicKeyInfo; the provider's
/// path by SHA-1 of the BIT STRING. Both computed here from the key's SPKI.
#[test]
fn applet_key_files_use_the_applet_key_id() {
    use sha1::{Digest, Sha1};
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for (spec, prefix) in [
        (KeySpec::Gost2004, "GOSTKNCA_"),
        (KeySpec::RsaSha256(2048), "RSA256_"),
    ] {
        let dir = TempDir::new().unwrap();
        let key = generate(spec).unwrap();
        let spki = key.public_key().to_spki();
        let whole = hex(&Sha1::digest(spki.to_der().unwrap()));
        let bits = hex(&Sha1::digest(spki.subject_public_key.raw_bytes()));
        assert_ne!(whole, bits);
        assert_eq!(applet_key_id(&key.public_key()), whole);
        assert_eq!(key_id(&key.public_key()), bits);

        let path = create_applet_key_file(dir.path(), &key, spec, DEFAULT_PASSWORD).unwrap();
        assert_eq!(path, dir.path().join(format!("{prefix}{whole}.p12")));
        // The reader pairs the keyless key by its localKeyId, the applet identifier.
        let contents = load_contents(&fs::read(&path).unwrap(), DEFAULT_PASSWORD).unwrap();
        assert_eq!(contents.keys[0].alias, whole);
        assert_eq!(contents.keys[0].key.public_key(), key.public_key());
        // The key bag's `localKeyId` is that identifier (Kalkan writes the hex-decoded
        // alias), not the BIT STRING hash; key bag attributes are not encrypted.
        let bytes = fs::read(&path).unwrap();
        assert!(contains(
            &bytes,
            &local_key_id_attribute(&hex_decode(&whole))
        ));
        assert!(!contains(
            &bytes,
            &local_key_id_attribute(&hex_decode(&bits))
        ));

        // A certificate whose SKI is that identifier installs into the file.
        let mut spec_cert = TestCertSpec::from_cert(&certificate(spec, &key, Profile::default()));
        spec_cert.extensions[0] = extension(
            SubjectKeyIdentifier::OID,
            &SubjectKeyIdentifier(OctetString::new(hex_decode(&whole)).unwrap()),
        );
        let cert = issue_cert(&issuer(spec), spec_cert);
        assert_eq!(
            install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12),
            Ok(path.clone())
        );
        let entries = load(&fs::read(&path).unwrap(), DEFAULT_PASSWORD).unwrap();
        assert_eq!(entries[0].alias, whole);
        assert_eq!(entries[0].cert, cert);
    }
}

#[test]
fn folder_search_bounds() {
    // Every folder: a file over the size limit sorts first and is skipped unread.
    let (dir, key, path) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    let huge = fs::File::create(dir.path().join("0-huge.p12")).unwrap();
    huge.set_len(MAX_KEY_FILE + 1).unwrap();
    drop(huge);
    assert_eq!(
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12),
        Ok(path)
    );

    // A folder the user picked is searched whole; a page-named one only within bounds.
    let (dir, key, path) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    for i in 0..MAX_KEY_FILES {
        fs::write(dir.path().join(format!("0-{i:03}.p12")), b"x").unwrap();
    }
    let err = install_certificate_in_page_folder(
        dir.path(),
        DEFAULT_PASSWORD,
        &cert,
        &oid::STORAGE_PKCS12,
    )
    .unwrap_err();
    assert!(
        matches!(err, KeystoreError::KeystoreFileNotFound(_)),
        "{err:?}"
    );
    assert_eq!(
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12),
        Ok(path)
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// DER of the `localKeyId` attribute (`1.2.840.113549.1.9.21`) with `id`.
fn local_key_id_attribute(id: &[u8]) -> Vec<u8> {
    let mut attribute = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21")
        .to_der()
        .unwrap();
    attribute.extend([0x31, id.len() as u8 + 2, 0x04, id.len() as u8]);
    attribute.extend(id);
    attribute
}

#[test]
fn change_password_of_read_bytes() {
    let (_dir, _, path) = key_file(KeySpec::Gost2015_512);
    let bytes = fs::read(&path).unwrap();
    // The bytes given are what is re-encrypted; the file is only written.
    fs::write(&path, b"replaced").unwrap();
    change_password_data(&path, &bytes, DEFAULT_PASSWORD, "Secret123").unwrap();
    let contents = load_contents(&fs::read(&path).unwrap(), "Secret123").unwrap();
    assert_eq!(contents.keys.len(), 1);
    assert_eq!(
        change_password_data(&path, &bytes, DEFAULT_PASSWORD, "short"),
        Err(KeystoreError::WrongPasswordPattern { empty: false })
    );
}

#[test]
fn change_password_after_install() {
    let (dir, key, path) = key_file(KeySpec::Gost2015_512);
    let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
    install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();

    let err = change_password(&path, "Wrong123", "Secret123").unwrap_err();
    assert_eq!(err, KeystoreError::WrongPassword);
    assert_eq!(err.provider_code(), Some("WRONG_KEYSTORE_PASSWORD"));

    change_password(&path, DEFAULT_PASSWORD, "Secret123").unwrap();
    let p12 = fs::read(&path).unwrap();
    assert!(matches!(
        load(&p12, DEFAULT_PASSWORD),
        Err(Pkcs12Error::WrongPassword)
    ));
    let entries = load(&p12, "Secret123").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cert, cert);
    assert_pair(&entries[0], KeySpec::Gost2015_512);
    assert_eq!(file_names(dir.path()).len(), 1, "no temporary file left");
}

#[test]
fn change_password_keeps_keyless_keys_and_other_certificates() {
    // A key without a certificate: the original's check lets it through.
    let (_dir, key, path) = key_file(KeySpec::Gost2004);
    change_password(&path, DEFAULT_PASSWORD, "Secret123").unwrap();
    let contents = load_contents(&fs::read(&path).unwrap(), "Secret123").unwrap();
    assert_eq!(contents.keys.len(), 1);
    assert!(contents.keys[0].cert.is_none());
    assert_eq!(contents.keys[0].key.public_key(), key.public_key());

    // Certificates that pair with no key (here a CA certificate) stay.
    let entry = issuer(KeySpec::RsaSha256(2048));
    let ca = read(oncl_testkit::fixture("nca/prod/ncarsa22.der"));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.p12");
    let p12 = pkcs12::write(
        &[WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry.key.to_pkcs8_der().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        std::slice::from_ref(&ca),
        DEFAULT_PASSWORD,
        &WriteOptions::default(),
        &mut |buf| buf.fill(9),
    )
    .unwrap();
    fs::write(&path, p12).unwrap();
    change_password(&path, DEFAULT_PASSWORD, "Secret123").unwrap();
    let contents = load_contents(&fs::read(&path).unwrap(), "Secret123").unwrap();
    assert_eq!(contents.keys.len(), 1);
    assert_eq!(contents.keys[0].cert.as_ref(), Some(&entry.cert));
    assert_eq!(contents.other_certs.len(), 1);
    assert_eq!(contents.other_certs[0].to_der().unwrap(), ca);
}

#[test]
fn change_password_needs_a_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.p12");
    let p12 = pkcs12::write(
        &[],
        &[],
        DEFAULT_PASSWORD,
        &WriteOptions::default(),
        &mut |buf| buf.fill(1),
    )
    .unwrap();
    fs::write(&path, &p12).unwrap();
    let err = change_password(&path, DEFAULT_PASSWORD, "Secret123").unwrap_err();
    assert_eq!(err, KeystoreError::ChangePasswordConstraint);
    assert_eq!(err.provider_code(), Some("CHANGE_PASSWORD_CONSTRAINT"));
    assert_eq!(fs::read(&path).unwrap(), p12);

    let err = change_password(
        &dir.path().join("missing.p12"),
        DEFAULT_PASSWORD,
        "Secret123",
    )
    .unwrap_err();
    assert!(matches!(err, KeystoreError::Io(_)), "{err:?}");
}

#[test]
fn password_pattern() {
    for good in [
        "Qwerty12",
        "a1b2c3",
        "1.?#$^+=!*()@%&_-a",
        &format!("a{}", "1".repeat(31)),
    ] {
        assert_eq!(check_password_pattern(good), Ok(()), "{good}");
    }
    let empty = check_password_pattern("").unwrap_err();
    assert_eq!(empty, KeystoreError::WrongPasswordPattern { empty: true });
    assert_eq!(empty.to_string(), "Пустой пароль не допускается.");
    for bad in [
        "a1b2c",
        "abcdefgh",
        "12345678",
        "пароль123",
        "Qwerty 12",
        "Qwerty12~",
        &format!("a{}", "1".repeat(32)),
    ] {
        let err = check_password_pattern(bad).unwrap_err();
        assert_eq!(
            err,
            KeystoreError::WrongPasswordPattern { empty: false },
            "{bad}"
        );
        assert_eq!(err.provider_code(), Some("WRONG_PASSWORD_PATTERN"));
    }

    // The pattern is checked before the file is even read.
    let (_dir, _, path) = key_file(KeySpec::Gost2015_512);
    let before = fs::read(&path).unwrap();
    let err = change_password(&path, "Wrong123", "short").unwrap_err();
    assert_eq!(err, KeystoreError::WrongPasswordPattern { empty: false });
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn key_files_stay_owner_only() {
        let (dir, key, path) = key_file(KeySpec::Gost2015_512);
        assert_eq!(mode(&path), 0o600, "a new key file");

        let cert = certificate(KeySpec::Gost2015_512, &key, Profile::default());
        install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
        assert_eq!(mode(&path), 0o600, "after install_certificate");
        change_password(&path, DEFAULT_PASSWORD, "Secret123").unwrap();
        assert_eq!(mode(&path), 0o600, "after change_password");

        // A key file someone made world-readable is owner-only again once rewritten.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        change_password(&path, "Secret123", "Secret456").unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    /// APFS refuses file names that are not UTF-8, so macOS has no such key files.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_utf8_key_file_names_keep_their_name_under_auth() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let (dir, key, path) = key_file(KeySpec::RsaSha256(2048));
        let name = OsStr::from_bytes(b"RSA256_\xff\xfe.p12");
        let odd = dir.path().join(name);
        fs::rename(&path, &odd).unwrap();
        let cert = certificate(
            KeySpec::RsaSha256(2048),
            &key,
            Profile {
                auth: true,
                ..Profile::default()
            },
        );
        let installed =
            install_certificate(dir.path(), DEFAULT_PASSWORD, &cert, &oid::STORAGE_PKCS12).unwrap();
        assert_eq!(
            installed.file_name().unwrap().as_bytes(),
            b"AUTH_RSA256_\xff\xfe.p12"
        );
        assert_eq!(mode(&installed), 0o600);
        assert_eq!(
            load(&fs::read(&installed).unwrap(), DEFAULT_PASSWORD)
                .unwrap()
                .len(),
            1
        );
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// Windows resolves `..` lexically, so `<key file>\a\..` reads the key file; rewriting
    /// it through that path must fail and keep the key file.
    #[test]
    fn change_password_through_dot_dot_keeps_the_key_file() {
        let (dir, _, path) = key_file(KeySpec::Gost2015_512);
        let before = fs::read(&path).unwrap();
        let mut through = path.as_os_str().to_owned();
        through.push(r"\a\..");
        let through = Path::new(&through);
        assert_eq!(
            fs::read(through).unwrap(),
            before,
            "Windows opens the key file"
        );

        let err = change_password(through, DEFAULT_PASSWORD, "Secret123").unwrap_err();
        assert!(matches!(err, KeystoreError::Io(_)), "{err:?}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(file_names(dir.path()).len(), 1, "no temporary file left");
    }
}
