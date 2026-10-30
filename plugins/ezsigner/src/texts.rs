//! The module's messages in Russian and Kazakh, as its message bundles have them (the
//! Russian path text ends with a line break, the typos are the original's).

/// The language of the messages: `kk` from the page's `lang`, Russian otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Russian.
    Ru,
    /// Kazakh.
    Kk,
}

impl Lang {
    /// The language `lang` selects.
    pub fn of(lang: &str) -> Lang {
        if lang == "kk" { Lang::Kk } else { Lang::Ru }
    }
}

/// A message of the module's bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text {
    NoSuchMethod,
    InternalError,
    NonexistentPath,
    Required,
    CmsSigned,
    FileIo,
    ActionCanceled,
    KeyNotFound,
    KeyChoose,
    DirChoose,
    CertExpired,
    CertNotYetValid,
    UnknownCa,
    OcspUnknown,
    OcspNotVerified,
    OcspException,
    OcspRevoked,
    CertVerification,
    CertType,
}

impl Text {
    /// The bundle key, as `getMessage(key)` takes it.
    pub fn key(self) -> &'static str {
        match self {
            Text::NoSuchMethod => "module.NoSuchMethodException",
            Text::InternalError => "internalError",
            Text::NonexistentPath => "error.nonexistent.filepath",
            Text::Required => "404",
            Text::CmsSigned => "cms.signed",
            Text::FileIo => "file.ioException",
            Text::ActionCanceled => "action.canceled",
            Text::KeyNotFound => "keyNotFound",
            Text::KeyChoose => "key.choose",
            Text::DirChoose => "dir.choose",
            Text::CertExpired => "cert.expired",
            Text::CertNotYetValid => "cert.not_yet_valid",
            Text::UnknownCa => "error.certificate.ca",
            Text::OcspUnknown => "error.certificate.ocsp.unknown",
            Text::OcspNotVerified => "error.certificate.ocsp.not_verified",
            Text::OcspException => "ocsp.exception",
            Text::OcspRevoked => "ocsp.revoked",
            Text::CertVerification => "cert.verification.error",
            Text::CertType => "error.certificate.type",
        }
    }

    /// Every message.
    pub const ALL: [Text; 19] = [
        Text::NoSuchMethod,
        Text::InternalError,
        Text::NonexistentPath,
        Text::Required,
        Text::CmsSigned,
        Text::FileIo,
        Text::ActionCanceled,
        Text::KeyNotFound,
        Text::KeyChoose,
        Text::DirChoose,
        Text::CertExpired,
        Text::CertNotYetValid,
        Text::UnknownCa,
        Text::OcspUnknown,
        Text::OcspNotVerified,
        Text::OcspException,
        Text::OcspRevoked,
        Text::CertVerification,
        Text::CertType,
    ];

    /// The message with this bundle key.
    pub fn of_key(key: &str) -> Option<Text> {
        Text::ALL.into_iter().find(|t| t.key() == key)
    }

    /// The text in `lang`.
    pub fn get(self, lang: Lang) -> &'static str {
        let (ru, kk) = match self {
            Text::NoSuchMethod => ("В модуле нет такого метода", "Модульде мұндай әдіс жоқ"),
            Text::InternalError => ("Непредвиденная ошибка", "Күтпеген қате"),
            Text::NonexistentPath => (
                "Этот путь к файлу не существует на вашем компьютере.\n",
                "Бұл файлға жол сіздің компьютеріңіз де жоқ.",
            ),
            Text::Required => (
                "Не заполнены обязательные входные параметры",
                "Міндетті кіріс параметрлер толтырылған жоқ",
            ),
            Text::CmsSigned => ("Файл успешно подписан", "Файлға сәтті қол қойылды"),
            Text::FileIo => (
                "Ошибка при работе с файлом",
                "Файлмен жұмыс істеу кезіндегі қате",
            ),
            Text::ActionCanceled => ("Действие отменено", "Іс-қимыл жойылды"),
            Text::KeyNotFound => (
                "Сертификат указанного ключа не предназначен для подписания электронных документов",
                "Белгіленген кілттің сертификаты электронды құжаттарға қол қоюға арналмаған",
            ),
            Text::KeyChoose => ("Выберите ключ для подписи", "Қол қоюға кілтті таңдаңыз"),
            Text::DirChoose => ("Укажите директорию", "Буманы таңдаңыз"),
            Text::CertExpired => (
                "Срок действия сертфиката истек",
                "Сертификаттың жарамдылық мерзімі асты",
            ),
            Text::CertNotYetValid => (
                "Срок действия сертфикатa ещё не натупил",
                "Сертификаттың жарамдылық мерзімі әлі басталған жоқ",
            ),
            Text::UnknownCa => (
                "Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно",
                "Белгісіз куәландырушы орталық. Сертификаттардың тізбегін тексеру сәтсіз өтті.",
            ),
            Text::OcspUnknown => (
                "Не прошла проверка сертфиката через OCSP. Статус сертификата по OCSP - неизвестен",
                "Сертификат OCSP арқылы тексеруден өткен жоқ. OCSP бойынша сертификаттың статусы - белгісіз.",
            ),
            Text::OcspNotVerified => (
                "Ответ OCSP не прошел верификацию",
                "OCSP жауабы тексеруден өтпеді.",
            ),
            Text::OcspException => (
                "Сертификат не прошел проверку в сервисе OCSP. Убедитесь в точности даты и времени на вашем компьютере",
                "Сертификат OCSP сервисінде тексеруден өткен жоқ. Компьютеріңіздегі күн мен уақыттың дәл белгіленгеніне көз жеткізіңіз",
            ),
            // Unverified against the original: the Kazakh texts of these three (the
            // Russian ones stand in).
            Text::OcspRevoked => ("Сертификат отозван", "Сертификат отозван"),
            Text::CertVerification => (
                "Сертификат не прошел валидацию",
                "Сертификат не прошел валидацию",
            ),
            Text::CertType => (
                "Сертификат ключа не предназначен для подписания электронных документов",
                "Сертификат ключа не предназначен для подписания электронных документов",
            ),
        };
        match lang {
            Lang::Ru => ru,
            Lang::Kk => kk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_found() {
        for t in Text::ALL {
            assert_eq!(Text::of_key(t.key()), Some(t));
        }
        assert_eq!(Text::of_key("nope"), None);
    }

    #[test]
    fn languages() {
        assert_eq!(Lang::of("kk"), Lang::Kk);
        assert_eq!(Lang::of("en"), Lang::Ru);
        assert_eq!(Lang::of(""), Lang::Ru);
        assert!(Text::NonexistentPath.get(Lang::Ru).ends_with('\n'));
        assert!(!Text::NonexistentPath.get(Lang::Kk).ends_with('\n'));
    }
}
