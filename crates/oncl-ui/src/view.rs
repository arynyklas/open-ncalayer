//! Dialog texts Rust composes, in the request's [`Locale`]: key and certificate rows,
//! storage names, open errors and new password checks. Fixed dialog texts live in the
//! `.slint` files and their `.po` catalogs.

use oncl_basics::{
    Availability, DisabledReason, ImportPrompt, KeyPrompt, Locale, OpenError, StorageKind,
};
use oncl_pki::info::CertInfo;
use time::OffsetDateTime;

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
    /// Why it may not be picked.
    pub note: Option<String>,
    /// The revocation mark the row shows: `revoked <date>`.
    pub revoked: Option<String>,
}

/// The rows of the key dialog, one per candidate in order.
pub fn key_rows(p: &KeyPrompt) -> Vec<KeyRow> {
    let t = Texts::of(p.locale);
    p.candidates
        .iter()
        .map(|c| {
            let info = &c.info;
            let details = cert_details(info, t, None);
            let revoked = match &c.availability {
                Availability::Revoked { time } => Some(format!("{} {}", t.revoked, date(*time))),
                _ => None,
            };
            let note = match &c.availability {
                Availability::Enabled => None,
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
                note,
                revoked,
            }
        })
        .collect()
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

/// Why a storage answer could not be opened.
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
        (OpenError::NoKeys, Locale::Kk) => "Қоймада кілттер жоқ",
        (OpenError::NoKeys, Locale::Ru) => "В хранилище нет ключей",
        (OpenError::NoKeys, Locale::En) => "The key store holds no keys",
        (OpenError::UnsupportedStorage, Locale::Kk) => "Таңдалған қоймаға қолдау көрсетілмейді",
        (OpenError::UnsupportedStorage, Locale::Ru) => "Выбранное хранилище не поддерживается",
        (OpenError::UnsupportedStorage, Locale::En) => "The chosen storage is not supported",
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
                chain: "The certificate does not chain to a trusted certification authority",
                revoked: "revoked",
                serial: "serial",
            },
        }
    }

    fn reason(&self, r: DisabledReason) -> &'static str {
        match r {
            DisabledReason::ExtKeyUsage => self.eku,
            DisabledReason::Iin => self.iin_differs,
            DisabledReason::Bin => self.bin_differs,
            DisabledReason::SerialNumber => self.serial_differs,
            DisabledReason::Chain => self.chain,
        }
    }
}
