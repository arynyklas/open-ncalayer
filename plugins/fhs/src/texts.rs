//! The texts of the original's windows: Russian (`Cabinet_ru`), the Russian of
//! `Cabinet_kz` for Kazakh, and English (`Cabinet_en`).

use oncl_pdk::Locale;

/// The texts of one language.
pub struct Texts {
    /// The file chooser's title.
    pub select_certificate: &'static str,
    /// The file chooser's file type.
    pub key_store: &'static str,
    /// The error window's title.
    pub error: &'static str,
    /// Its button.
    pub close: &'static str,
    /// No key chosen.
    pub key_not_selected: &'static str,
    /// The file did not download.
    pub download_failed: &'static str,
    /// The time-stamp failed.
    pub tsp_failed: &'static str,
    /// The signature failed.
    pub sign_failed: &'static str,
}

/// `Cabinet_ru`, the typo of its time-stamp text kept.
const RU: Texts = Texts {
    select_certificate: "Выберите сертификат",
    key_store: "Хранилище ключей",
    error: "Ошибка",
    close: "Закрыть",
    key_not_selected: "Не выбран ключ ЭЦП",
    download_failed: "Ошибка при скачивании файла",
    tsp_failed: "Ошибка при формирвоании метки времени",
    sign_failed: "Ошибка при формировании ЭЦП",
};

/// `Cabinet_kz`: Russian, its time-stamp text spelled right.
const KZ: Texts = Texts {
    tsp_failed: "Ошибка при формировании метки времени",
    ..RU
};

/// `Cabinet_en`: some of its texts are Russian.
const EN: Texts = Texts {
    select_certificate: "Select certificate",
    key_store: "Хранилище ключей",
    error: "Error",
    close: "Close",
    key_not_selected: "Key entry not selected",
    download_failed: "File download error",
    tsp_failed: "Error on create Timestamp",
    sign_failed: "Ошибка при формировании ЭЦП",
};

/// The texts of `locale`.
pub fn of(locale: Locale) -> &'static Texts {
    match locale {
        Locale::Ru => &RU,
        Locale::Kk => &KZ,
        Locale::En => &EN,
    }
}
