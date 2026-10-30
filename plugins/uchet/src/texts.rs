//! The module's Russian messages (its bundle `dictionary_ru`, the only one it reads).

/// `getMessage(key)`: the bundle's text of `key`.
pub fn message(key: &str) -> Option<&'static str> {
    BUNDLE
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, text)| *text)
}

/// The bundle's keys and texts the module answers with.
const BUNDLE: [(&str, &str); 14] = [
    ("404", REQUIRED),
    ("internalError", INTERNAL_ERROR),
    ("cms.signed", CMS_SIGNED),
    ("file.ioException", FILE_IO),
    ("action.canceled", "Действие отменено"),
    ("keyNotFound", KEY_NOT_FOUND),
    ("key.choose", KEY_CHOOSE),
    ("dir.choose", "Укажите директорию"),
    ("cert.expired", CERT_EXPIRED),
    ("cert.not_yet_valid", CERT_NOT_YET_VALID),
    ("error.certificate.ca", UNKNOWN_CA),
    ("error.certificate.ocsp.unknown", OCSP_UNKNOWN),
    ("error.certificate.ocsp.not_verified", OCSP_NOT_VERIFIED),
    ("ocsp.exception", OCSP_EXCEPTION),
];

pub const REQUIRED: &str = "Не заполнены обязательные входные параметры";
pub const INTERNAL_ERROR: &str = "Непредвиденная ошибка";
pub const CMS_SIGNED: &str = "Файл успешно подписан";
pub const FILE_IO: &str = "Ошибка при работе с файлом";
pub const KEY_NOT_FOUND: &str =
    "Сертификат указанного ключа не предназначен для подписания электронных документов";
pub const KEY_CHOOSE: &str = "Выберите ключ для подписи";
pub const CERT_EXPIRED: &str = "Срок действия сертфиката истек";
pub const CERT_NOT_YET_VALID: &str = "Срок действия сертфикатa ещё не натупил";
pub const UNKNOWN_CA: &str =
    "Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно";
pub const OCSP_UNKNOWN: &str =
    "Не прошла проверка сертфиката через OCSP. Статус сертификата по OCSP - неизвестен";
pub const OCSP_NOT_VERIFIED: &str = "Ответ OCSP не прошел верификацию";
pub const OCSP_EXCEPTION: &str = "Сертификат не прошел проверку в сервисе OCSP. Убедитесь в точности даты и времени на вашем компьютере";
pub const REVOKED: &str = "Сертификат отозван";
pub const NOT_VALIDATED: &str = "Сертификат не прошел валидацию";
pub const NOT_FOR_SIGNING: &str =
    "Сертификат ключа не предназначен для подписания электронных документов";
pub const NO_TIMESTAMP: &str = "Отсутствует метка времени";
pub const TIMESTAMP_INVALID: &str = "Метка времени не прошла валидацию";
pub const SIGNER_VALIDITY: &str = "Срок действия сертфиката истек или ещё не натупил";
pub const NO_MEDIUM: &str = "Носитель не обнаружен";
pub const STORE_NOT_OPENED: &str = "Не удалось открыть хранилище";
pub const LICENSE_DOWN: &str = "Сервер лицензирования не доступен";
