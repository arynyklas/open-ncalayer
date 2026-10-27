use oncl_basics::{
    Action, Availability, DisabledReason, FileKind, ImportPrompt, KeyCandidate, KeyPrompt,
    LiveAvailability, Locale, OpenError, StorageKind,
};
use oncl_pki::info::{CertInfo, KeyUsageBits};
use oncl_ui::view::{
    CertRow, cert_rows, error_text, file_dialog_title, file_filter_name, folder_error, key_rows,
    new_password_error,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use time::macros::datetime;

const IIN: &str = "123456789011";

fn cert(cn: &str, iin: Option<&str>, bin: Option<&str>, org: Option<&str>) -> CertInfo {
    CertInfo {
        subject_cn: Some(cn.to_owned()),
        iin: iin.map(str::to_owned),
        bin: bin.map(str::to_owned),
        organization: org.map(str::to_owned),
        serial_hex: "01".to_owned(),
        not_before: datetime!(2024-03-01 12:00 UTC),
        not_after: datetime!(2025-03-01 12:00 UTC),
        ext_key_usages: BTreeSet::new(),
        key_usage: KeyUsageBits::default(),
        signature_alg_oid: "1.2.398.3.10.1.1.2.3.2".to_owned(),
        spki_alg_oid: "1.2.398.3.10.1.1.2.3.2".to_owned(),
        ocsp_no_check: false,
    }
}

fn candidate(info: CertInfo, availability: Availability) -> KeyCandidate {
    KeyCandidate {
        alias: "alias".to_owned(),
        info,
        availability,
    }
}

fn enabled(cn: &str, iin: &str) -> KeyCandidate {
    candidate(cert(cn, Some(iin), None, None), Availability::Enabled)
}

fn expired(cn: &str, iin: &str) -> KeyCandidate {
    candidate(cert(cn, Some(iin), None, None), Availability::Expired)
}

fn disabled(cn: &str, bin: &str, org: &str, reasons: Vec<DisabledReason>) -> KeyCandidate {
    candidate(
        cert(cn, Some(IIN), Some(bin), Some(org)),
        Availability::Disabled(reasons),
    )
}

fn prompt<const N: usize>(locale: Locale, candidates: [KeyCandidate; N]) -> KeyPrompt {
    let live =
        LiveAvailability::settled(candidates.iter().map(|c| c.availability.clone()).collect());
    KeyPrompt {
        origin: "https://example.kz".to_owned(),
        locale,
        action: Action::Sign,
        candidates: candidates.into(),
        live,
        detail: None,
        error: None,
    }
}

#[test]
fn rows_for_mixed_candidates() {
    let rows = key_rows(&prompt(
        Locale::Ru,
        [
            enabled("ТЕСТОВ ТЕСТ", IIN),
            expired("ТЕСТОВ ТЕСТ", IIN),
            disabled(
                "ТЕСТОВ ТЕСТ",
                "123456789021",
                "ТОО «Тест»",
                vec![DisabledReason::Iin],
            ),
        ],
    ));
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].title, "ТЕСТОВ ТЕСТ");
    assert!(rows[0].enabled && rows[0].details.contains("ИИН 123456789011"));
    assert!(
        rows[0]
            .details
            .contains("действителен 01.03.2024 – 01.03.2025"),
        "{}",
        rows[0].details
    );
    assert_eq!(rows[0].note, None);
    assert!(rows.iter().all(|r| r.revoked.is_none()));
    assert!(!rows[1].enabled && rows[1].note.as_deref().unwrap().contains("истёк"));
    assert!(!rows[2].enabled && rows[2].note.as_deref().unwrap().contains("ИИН"));
    assert!(
        rows[2]
            .details
            .starts_with("БИН 123456789021 · ТОО «Тест» · "),
        "{}",
        rows[2].details
    );
}

#[test]
fn every_reason_is_listed_in_the_locale() {
    let reasons = vec![
        DisabledReason::ExtKeyUsage,
        DisabledReason::Iin,
        DisabledReason::Bin,
        DisabledReason::SerialNumber,
        DisabledReason::Chain,
    ];
    let rows = key_rows(&prompt(
        Locale::Kk,
        [disabled("TEST", "123456789021", "TEST LLP", reasons)],
    ));
    let note = rows[0].note.as_deref().unwrap();
    assert!(note.contains("ЖСН") && note.contains("БСН"), "{note}");
    assert!(note.contains("тізбегі"), "{note}");
    assert!(rows[0].details.contains("жарамды"), "{}", rows[0].details);
}

#[test]
fn revoked_key_is_marked_with_its_date_and_disabled() {
    let time = datetime!(2026-02-03 04:05:06 UTC);
    let revoked = || {
        candidate(
            cert("ТЕСТОВ ТЕСТ", Some(IIN), None, None),
            Availability::Revoked { time },
        )
    };
    for (locale, mark) in [
        (Locale::Ru, "отозван 03.02.2026"),
        (Locale::Kk, "кері қайтарылған 03.02.2026"),
        (Locale::En, "revoked 03.02.2026"),
    ] {
        let rows = key_rows(&prompt(locale, [revoked(), enabled("ДРУГОЙ", IIN)]));
        assert!(!rows[0].enabled);
        assert_eq!(rows[0].revoked.as_deref(), Some(mark));
        assert_eq!(rows[0].note.as_deref(), Some(mark));
        assert!(rows[1].enabled && rows[1].revoked.is_none());
    }
}

#[test]
fn pending_key_is_not_enabled_and_has_no_note() {
    let pending = candidate(
        cert("ТЕСТОВ ТЕСТ", Some(IIN), None, None),
        Availability::Pending,
    );
    let rows = key_rows(&prompt(Locale::Ru, [pending, expired("ДРУГОЙ", IIN)]));
    assert!(!rows[0].enabled && rows[0].pending);
    assert_eq!(rows[0].note, None);
    assert_eq!(rows[0].revoked, None);
    assert!(!rows[1].pending);
}

#[test]
fn kazakh_and_english_texts_differ() {
    assert_ne!(
        error_text(OpenError::WrongPassword, Locale::Kk),
        error_text(OpenError::WrongPassword, Locale::En)
    );
}

#[test]
fn certificate_rows_show_the_serial() {
    let mut no_cn = cert("x", None, None, None);
    no_cn.subject_cn = None;
    no_cn.serial_hex = "4105a0".to_owned();
    let p = ImportPrompt {
        origin: "https://example.kz".to_owned(),
        locale: Locale::Ru,
        storage: StorageKind::Pkcs12,
        path: None,
        certificates: vec![cert("ТЕСТОВ ТЕСТ", Some(IIN), None, None), no_cn],
    };
    assert_eq!(
        cert_rows(&p),
        [
            CertRow {
                title: "ТЕСТОВ ТЕСТ".to_owned(),
                details: format!(
                    "ИИН {IIN} · серийный номер 01 · действителен 01.03.2024 – 01.03.2025"
                ),
            },
            CertRow {
                title: "4105a0".to_owned(),
                details: "серийный номер 4105a0 · действителен 01.03.2024 – 01.03.2025".to_owned(),
            },
        ]
    );
}

#[test]
fn new_passwords_follow_the_import_pattern() {
    for ok in ["Abcde1", "Pass.word#12", &format!("A1{}", "b".repeat(30))] {
        assert_eq!(new_password_error(ok, ok, Locale::En), None, "{ok:?}");
    }
    let pattern = new_password_error("abc", "abc", Locale::En).unwrap();
    for bad in [
        "Abcd1",
        "abcdef1",
        "ABCDEF1",
        "Abcdefg",
        "Abc def1",
        "Пароль1a",
        "Abc1~xyz",
        &format!("A1{}", "b".repeat(31)),
    ] {
        assert_eq!(
            new_password_error(bad, bad, Locale::En),
            Some(pattern),
            "{bad:?}"
        );
    }
    // A mismatch is reported first, as in the original.
    let mismatch = new_password_error("Abcde1", "Abcde2", Locale::En).unwrap();
    assert_ne!(mismatch, pattern);
    assert_eq!(new_password_error("abc", "abd", Locale::En), Some(mismatch));
    assert_ne!(
        new_password_error("Abcde1", "x", Locale::Ru),
        new_password_error("Abcde1", "x", Locale::Kk)
    );
}

/// The certificate request dialog refuses a folder that is not a full path before it
/// closes, so the user can correct it; the text alone decides.
#[test]
fn csr_folder_must_be_a_full_path() {
    let absolute = std::env::temp_dir().join("oncl-missing-folder");
    assert_eq!(folder_error(absolute.to_str().unwrap(), Locale::Ru), None);
    for relative in ["", "keys", "./keys", r"..\keys"] {
        assert_eq!(
            folder_error(relative, Locale::Ru),
            Some("Укажите полный путь к папке хранения ключа"),
            "{relative:?}"
        );
    }
    assert_ne!(
        folder_error("keys", Locale::Kk),
        folder_error("keys", Locale::En)
    );
}

/// Every `@tr` string of the dialogs has a Kazakh and a Russian translation, and the
/// catalogs hold nothing else.
#[test]
fn every_slint_string_is_translated() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source = BTreeSet::new();
    for entry in std::fs::read_dir(dir.join("ui")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for (_, rest) in text
            .match_indices("@tr(\"")
            .map(|(i, _)| text.split_at(i + 5))
        {
            source.insert(rest[..rest.find('"').unwrap()].to_owned());
        }
    }
    assert!(!source.is_empty());
    for lang in ["kk", "ru"] {
        let po = dir.join(format!("po/{lang}/LC_MESSAGES/oncl-ui.po"));
        let catalog = po_entries(&std::fs::read_to_string(&po).unwrap());
        assert_eq!(
            catalog.keys().cloned().collect::<BTreeSet<_>>(),
            source,
            "{}",
            po.display()
        );
        for (id, text) in &catalog {
            assert!(!text.is_empty(), "{lang}: {id:?} is not translated");
        }
    }
}

/// `msgid` → `msgstr` of a catalog of single-line entries, without the header.
fn po_entries(po: &str) -> BTreeMap<String, String> {
    let unquote = |line: &str, key: &str| {
        line.strip_prefix(key)
            .map(|v| v.trim().trim_matches('"').to_owned())
    };
    let mut entries = BTreeMap::new();
    let mut id = None;
    for line in po.lines() {
        if let Some(v) = unquote(line, "msgid ") {
            id = Some(v);
        } else if let Some(v) = unquote(line, "msgstr ")
            && let Some(id) = id.take().filter(|id| !id.is_empty())
        {
            entries.insert(id, v);
        }
    }
    entries
}

#[test]
fn file_chooser_texts() {
    assert_eq!(
        file_dialog_title(FileKind::Directory, Locale::Ru),
        "Выберите папку"
    );
    assert_eq!(
        file_dialog_title(FileKind::Cer, Locale::Kk),
        "Файлды таңдаңыз"
    );
    assert_eq!(
        file_dialog_title(FileKind::All, Locale::En),
        "Choose a file"
    );
    assert_eq!(file_filter_name(FileKind::Cer), "*.der, *.cer");
    assert_eq!(file_filter_name(FileKind::Crl), "*.crl");
}
