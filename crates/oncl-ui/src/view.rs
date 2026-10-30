//! Dialog texts Rust composes, in the request's [`Locale`]: key and certificate rows,
//! storage names, open errors, new password and folder checks and the file chooser's title
//! and filter. Fixed dialog texts live in the `.slint` files and their `.po` catalogs.

use oncl_basics::{
    Availability, DisabledReason, FileKind, ImportPrompt, KeyCandidate, KeyPrompt, Locale,
    OpenError, StorageKind,
};
use oncl_pki::info::CertInfo;
use std::path::Path;
use time::OffsetDateTime;

/// The longest text of a page shown in a notification or a window, in characters.
pub const MAX_PAGE_TEXT: usize = 128;

/// `text` from a page (its origin, a name it sends) as a notification or a window shows it:
/// without control characters, line and paragraph separators (U+2028, U+2029) and
/// bidirectional controls (U+202A–U+202E, U+2066–U+2069), at most [`MAX_PAGE_TEXT`]
/// characters (then `…`).
pub fn page_text(text: &str) -> String {
    let shown = |c: &char| {
        !c.is_control()
            && !matches!(c, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    };
    let mut chars = text.chars().filter(shown);
    let mut shown: String = chars.by_ref().take(MAX_PAGE_TEXT).collect();
    if chars.next().is_some() {
        shown.push('…');
    }
    shown
}

/// Characters a new key file password may have besides Latin letters and digits (the
/// PKCS#12 password pattern).
const PASSWORD_SPECIALS: &str = ".?#$^+=!*()@%&_-";

/// A row of the key dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// Subject CN, or the key store alias without one.
    pub title: String,
    /// IIN, or BIN and organization; then the validity period.
    pub details: String,
    /// Whether the key may be picked.
    pub enabled: bool,
    /// Whether its certificate status is still being checked (it may not be picked yet).
    pub pending: bool,
    /// Why it may not be picked.
    pub note: Option<String>,
    /// The revocation mark the row shows: `revoked <date>`.
    pub revoked: Option<String>,
}

/// The rows of the key dialog, one per candidate in order.
pub fn key_rows(p: &KeyPrompt) -> Vec<KeyRow> {
    p.candidates.iter().map(|c| key_row(c, p.locale)).collect()
}

/// The key dialog's row of `c` in `l`.
pub fn key_row(c: &KeyCandidate, l: Locale) -> KeyRow {
    let t = Texts::of(l);
    let info = &c.info;
    let details = cert_details(info, t, None);
    let revoked = match &c.availability {
        Availability::Revoked { time } => Some(format!("{} {}", t.revoked, date(*time))),
        _ => None,
    };
    let note = match &c.availability {
        Availability::Enabled | Availability::Pending => None,
        Availability::Expired => Some(t.expired.to_owned()),
        Availability::Revoked { .. } => revoked.clone(),
        Availability::Disabled(reasons) => Some(
            reasons
                .iter()
                .map(|r| t.reason(*r))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    };
    KeyRow {
        title: info.subject_cn.clone().unwrap_or_else(|| c.alias.clone()),
        details,
        enabled: c.availability == Availability::Enabled,
        pending: c.availability == Availability::Pending,
        note,
        revoked,
    }
}

/// A certificate of the import dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRow {
    /// Subject CN, or the serial number without one.
    pub title: String,
    /// IIN, or BIN and organization; the serial number; the validity period.
    pub details: String,
}

/// The rows of the import dialog, one per certificate in order.
pub fn cert_rows(p: &ImportPrompt) -> Vec<CertRow> {
    let t = Texts::of(p.locale);
    p.certificates
        .iter()
        .map(|info| CertRow {
            title: info
                .subject_cn
                .clone()
                .unwrap_or_else(|| info.serial_hex.clone()),
            details: cert_details(info, t, Some(format!("{} {}", t.serial, info.serial_hex))),
        })
        .collect()
}

/// Why a new key file password (and its confirmation) is refused, as the original's import
/// dialog checks it: the two must match, then the password needs 6 to 32 characters with an
/// uppercase and a lowercase Latin letter and a digit. Only the characters of the PKCS#12
/// password pattern are allowed, so the key file accepts every password that passes.
pub fn new_password_error(password: &str, confirmation: &str, l: Locale) -> Option<&'static str> {
    let pattern = (6..=32).contains(&password.chars().count())
        && password
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || PASSWORD_SPECIALS.contains(c))
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_digit());
    if password != confirmation {
        Some(match l {
            Locale::Kk => "Енгізілген құпиясөздер сәйкес емес",
            Locale::Ru => "Введённые пароли не совпадают",
            Locale::En => "The passwords do not match",
        })
    } else if !pattern {
        Some(match l {
            Locale::Kk => {
                "Құпиясөз 6–32 таңбадан тұруы және кемінде бір бас латын әрпін, бір кіші латын әрпін және бір санды қамтуы керек; .?#$^+=!*()@%&_- таңбалары да рұқсат етіледі"
            }
            Locale::Ru => {
                "Пароль должен содержать от 6 до 32 символов, хотя бы одну заглавную и одну строчную латинскую букву и цифру; допускаются также символы .?#$^+=!*()@%&_-"
            }
            Locale::En => {
                "The password needs 6 to 32 characters with at least one uppercase and one lowercase Latin letter and a digit; .?#$^+=!*()@%&_- are allowed too"
            }
        })
    } else {
        None
    }
}

/// Why the folder of a certificate request is refused before the dialog closes: it must be
/// a full path (the key files are not written relative to the daemon's working directory).
/// Only the text is checked; whether the folder exists is the backend's check.
pub fn folder_error(path: &str, l: Locale) -> Option<&'static str> {
    (!Path::new(path).is_absolute()).then_some(match l {
        Locale::Kk => "Кілт сақталатын қалтаның толық жолын көрсетіңіз",
        Locale::Ru => "Укажите полный путь к папке хранения ключа",
        Locale::En => "Enter the full path of the key storage folder",
    })
}

/// Why a storage answer could not be opened. The texts for a store without (suitable) keys
/// (`label.errorMessage.emptyStorage*`) and for the legacy Applet's password checks are the
/// original's; English for the internal systems' policy is ours (the original's English
/// dictionary repeats the Kazakh text).
pub fn error_text(e: OpenError, l: Locale) -> &'static str {
    match (e, l) {
        (OpenError::WrongPassword, Locale::Kk) => "Құпиясөз қате",
        (OpenError::WrongPassword, Locale::Ru) => "Неверный пароль",
        (OpenError::WrongPassword, Locale::En) => "Wrong password",
        (OpenError::FileNotFound, Locale::Kk) => "Файл табылмады немесе оқылмайды",
        (OpenError::FileNotFound, Locale::Ru) => "Файл не найден или не читается",
        (OpenError::FileNotFound, Locale::En) => "The file cannot be found or read",
        (OpenError::NotPkcs12, Locale::Kk) => {
            "Файл PKCS#12 қоймасы емес немесе оған қолдау көрсетілмейді"
        }
        (OpenError::NotPkcs12, Locale::Ru) => {
            "Файл не является хранилищем PKCS#12 или не поддерживается"
        }
        (OpenError::NotPkcs12, Locale::En) => "The file is not a supported PKCS#12 key store",
        (OpenError::NotJks, Locale::Kk) => "Файл JKS қоймасы емес немесе оған қолдау көрсетілмейді",
        (OpenError::NotJks, Locale::Ru) => "Файл не является хранилищем JKS или не поддерживается",
        (OpenError::NotJks, Locale::En) => "The file is not a supported JKS key store",
        (OpenError::NoKeys, Locale::Kk) => "Сақтау орны бос.",
        (OpenError::NoKeys, Locale::Ru) => "Хранилище пустое.",
        (OpenError::NoKeys, Locale::En) => "Empty storage.",
        (OpenError::NoSigningKeys, Locale::Kk) => {
            "Тандалған сақтау орынында қол қоюға арналған кілттер табылмады"
        }
        (OpenError::NoSigningKeys, Locale::Ru) => {
            "В выбранном хранилище отсутствуют ключи для подписи"
        }
        (OpenError::NoSigningKeys, Locale::En) => "There are no keys for signing in the storage",
        (OpenError::NoAuthKeys, Locale::Kk) => {
            "Тандалған сақтау орынында аутентификацияға арналған кілттер табылмады"
        }
        (OpenError::NoAuthKeys, Locale::Ru) => {
            "В выбранном хранилище отсутствуют ключи для аутентификации"
        }
        (OpenError::NoAuthKeys, Locale::En) => {
            "There are no keys for authentication in the storage"
        }
        (OpenError::UnsupportedStorage, Locale::Kk) => "Таңдалған қоймаға қолдау көрсетілмейді",
        (OpenError::UnsupportedStorage, Locale::Ru) => "Выбранное хранилище не поддерживается",
        (OpenError::UnsupportedStorage, Locale::En) => "The chosen storage is not supported",
        // The legacy Applet's texts (`label.errorMessage.emptyField`,
        // `label.errorMessage.inPasswordPolicyNotSatisfied`).
        (OpenError::EmptyPassword, Locale::Kk) => "Бос алаң",
        (OpenError::EmptyPassword, Locale::Ru) => "Пустое поле",
        (OpenError::EmptyPassword, Locale::En) => "Empty field",
        (OpenError::InnerPasswordPolicy, Locale::Kk) => {
            "Құпиясөз кем дегенде 8 таңбадан құралып, оның ішінде 1 бас әріп, 1 кіші әріп (тек латын әріптері), 1 арнайы таңба және 1 сан болуы қажет."
        }
        (OpenError::InnerPasswordPolicy, Locale::Ru) => {
            "Пароль должен быть как минимум 8 символов и содержать 1 заглавную букву, 1 строчную букву (только латинские буквы), 1 специальный символ и 1 цифру."
        }
        (OpenError::InnerPasswordPolicy, Locale::En) => {
            "The password needs at least 8 characters with 1 uppercase letter, 1 lowercase letter (Latin letters only), 1 special character and 1 digit."
        }
    }
}

/// Name of a storage in the storage list.
pub fn storage_label(k: StorageKind, l: Locale) -> &'static str {
    match k {
        StorageKind::Pkcs12 => match l {
            Locale::Kk => "PKCS#12 файлы (.p12, .pfx)",
            Locale::Ru => "Файл PKCS#12 (.p12, .pfx)",
            Locale::En => "PKCS#12 file (.p12, .pfx)",
        },
        StorageKind::Jks => match l {
            Locale::Kk => "Java KeyStore файлы (.jks)",
            Locale::Ru => "Файл Java KeyStore (.jks)",
            Locale::En => "Java KeyStore file (.jks)",
        },
        StorageKind::Token("AKKaztokenStore") => "Kaztoken",
        StorageKind::Token("AKKZIDCardStore") => match l {
            Locale::Kk => "Жеке куәлік",
            Locale::Ru => "Удостоверение личности",
            Locale::En => "ID card",
        },
        StorageKind::Token("AKEToken72KStore") => "eToken 72K",
        StorageKind::Token("AKEToken5110Store") => "eToken 5110",
        StorageKind::Token("AKJaCartaStore") => "JaCarta",
        StorageKind::Token("AKAKEYStore") => "aKey",
        StorageKind::Token("ABCloudServiceStore") => match l {
            Locale::Kk => "Бұлттық қойма",
            Locale::Ru => "Облачное хранилище",
            Locale::En => "Cloud storage",
        },
        StorageKind::Token(name) => name,
    }
}

/// Title of the file chooser.
pub fn file_dialog_title(kind: FileKind, l: Locale) -> &'static str {
    match (kind == FileKind::Directory, l) {
        (true, Locale::Kk) => "Папканы таңдаңыз",
        (true, Locale::Ru) => "Выберите папку",
        (true, Locale::En) => "Choose a folder",
        (false, Locale::Kk) => "Файлды таңдаңыз",
        (false, Locale::Ru) => "Выберите файл",
        (false, Locale::En) => "Choose a file",
    }
}

/// Name of the file chooser's filter: its extensions as patterns, `*.der, *.cer`.
pub fn file_filter_name(kind: FileKind) -> String {
    kind.extensions()
        .iter()
        .map(|e| format!("*.{e}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `dd.MM.yyyy` in UTC.
fn date(t: OffsetDateTime) -> String {
    format!("{:02}.{:02}.{:04}", t.day(), u8::from(t.month()), t.year())
}

/// IIN, or BIN and organization; then `extra`; then the validity period.
fn cert_details(info: &CertInfo, t: &Texts, extra: Option<String>) -> String {
    let holder = match (&info.bin, &info.iin) {
        (Some(bin), _) => match &info.organization {
            Some(org) => Some(format!("{} {bin} · {org}", t.bin)),
            None => Some(format!("{} {bin}", t.bin)),
        },
        (None, Some(iin)) => Some(format!("{} {iin}", t.iin)),
        (None, None) => None,
    };
    let validity = format!(
        "{} {} – {}",
        t.valid,
        date(info.not_before),
        date(info.not_after)
    );
    [holder, extra, Some(validity)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Texts of [`key_rows`] and [`cert_rows`] in one language.
struct Texts {
    iin: &'static str,
    bin: &'static str,
    valid: &'static str,
    expired: &'static str,
    eku: &'static str,
    iin_differs: &'static str,
    bin_differs: &'static str,
    serial_differs: &'static str,
    tin_differs: &'static str,
    chain: &'static str,
    /// Followed by the revocation date.
    revoked: &'static str,
    /// Followed by the serial number.
    serial: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                iin: "ЖСН",
                bin: "БСН",
                valid: "жарамды",
                expired: "Сертификаттың қолданылу мерзімі өтті",
                eku: "Сертификат бұл операцияға арналмаған",
                iin_differs: "ЖСН сұралғанмен сәйкес келмейді",
                bin_differs: "БСН сұралғанмен сәйкес келмейді",
                serial_differs: "Сериялық нөмір сұралғанмен сәйкес келмейді",
                tin_differs: "ЖСН/БСН сұралғанмен сәйкес келмейді",
                chain: "Сертификаттың сенімді куәландырушы орталыққа дейінгі тізбегі құрылмады",
                revoked: "кері қайтарылған",
                serial: "сериялық нөмірі",
            },
            Locale::Ru => &Texts {
                iin: "ИИН",
                bin: "БИН",
                valid: "действителен",
                expired: "Срок действия сертификата истёк",
                eku: "Сертификат не предназначен для этой операции",
                iin_differs: "ИИН не совпадает с запрошенным",
                bin_differs: "БИН не совпадает с запрошенным",
                serial_differs: "Серийный номер не совпадает с запрошенным",
                tin_differs: "ИИН/БИН не совпадает с запрошенным",
                chain: "Цепочка сертификата не строится до доверенного удостоверяющего центра",
                revoked: "отозван",
                serial: "серийный номер",
            },
            Locale::En => &Texts {
                iin: "IIN",
                bin: "BIN",
                valid: "valid",
                expired: "The certificate has expired",
                eku: "The certificate is not meant for this operation",
                iin_differs: "The IIN differs from the requested one",
                bin_differs: "The BIN differs from the requested one",
                serial_differs: "The serial number differs from the requested one",
                tin_differs: "The IIN/BIN differs from the requested one",
                chain: "The certificate does not chain to a trusted certification authority",
                revoked: "revoked",
                serial: "serial",
            },
        }
    }

    fn reason(&self, r: DisabledReason) -> &'static str {
        match r {
            DisabledReason::ExtKeyUsage
            | DisabledReason::AnyExtKeyUsage
            | DisabledReason::ExcludedExtKeyUsage
            | DisabledReason::KncaType
            | DisabledReason::KeyUsage => self.eku,
            DisabledReason::Iin => self.iin_differs,
            DisabledReason::Bin => self.bin_differs,
            DisabledReason::SerialNumber => self.serial_differs,
            DisabledReason::Tin => self.tin_differs,
            DisabledReason::Chain => self.chain,
        }
    }
}
