//! The window texts of MarketSign, as its resource files have them. The Kazakh file holds
//! Russian texts.

use oncl_pdk::Locale;

/// The texts of one language.
pub struct Texts {
    /// The error window's title.
    pub error_title: &'static str,
    /// Its first button: back to the key dialog.
    pub close: &'static str,
    /// Its second button: stop.
    pub cancel: &'static str,
    /// Any failure to sign, text or XML.
    pub sign_xml_failed: &'static str,
    /// A request that does not read.
    pub bad_request: &'static str,
}

const RU: Texts = Texts {
    error_title: "Ошибка",
    close: "Закрыть",
    cancel: "Отменить",
    sign_xml_failed: "Ошибка при подписании XML",
    bad_request: "Ошибка при разборе запроса",
};

const EN: Texts = Texts {
    error_title: "Error",
    close: "Close",
    cancel: "Cancel",
    sign_xml_failed: "Ошибка при подписании XML",
    bad_request: "Ошибка при разборе запроса",
};

impl Texts {
    /// The texts of `locale`: Kazakh windows get the Kazakh file, whose texts are Russian.
    pub fn of(locale: Locale) -> &'static Texts {
        match locale {
            Locale::Ru | Locale::Kk => &RU,
            Locale::En => &EN,
        }
    }
}
