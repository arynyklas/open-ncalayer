//! The texts of K2Sign's windows, as its resource files have them (`ru`, `kk`, `en`; the
//! English file has Russian texts for many keys, typos included).

use oncl_pdk::Locale;

/// The error types of K2Sign: a site may name any of them in its reply, the page then gets
/// it as `errorCode`. Each with its texts in Russian, Kazakh and English; `None`: the
/// resource files lack the key and the window shows a single space.
// Unverified against the original: that the error types are exactly the keys of the
// resource files' error table (with the two that have no text).
pub const ERROR_TYPES: &[(&str, Option<[&str; 3]>)] = &[
    (
        "CANCEL",
        Some([
            "Отменено пользователем",
            "Пайдаланушы тоқтатқан",
            "Отменено пользователем",
        ]),
    ),
    (
        "MAX_FILE_SIZE_EXCEEDED",
        Some([
            "Превышен максимальный размер файла",
            "Файлдың ең үлкен мөлшерінен асты",
            "Превышен максимальный размер файла",
        ]),
    ),
    (
        "UPLOAD_FILE_EXCEPTION",
        Some([
            "Ошибка сохранения файла",
            "Файлды сақтау қатесі",
            "Ошибка сохранения файла",
        ]),
    ),
    (
        "UPLOAD_FILE_NOT_FOUND",
        Some(["Файл для с", "Файл для с", "Файл для с"]),
    ),
    (
        "CHECK_FILE_EXIST_ERROR",
        Some([
            "Ошибка: Файл не найден",
            "Қателік: Файл табылмады",
            "Ошибка: Файл не найден",
        ]),
    ),
    (
        "OTHER",
        Some(["Неизвестная ошибка", "Белгісіз қате", "Неизвестная ошибка"]),
    ),
    (
        "GET_SIGNATURE_FAILED",
        Some([
            "Ошибка получения подписи",
            "Қолтаңба алу кезіндегі қателік",
            "Ошибка получения подписи",
        ]),
    ),
    (
        "SELECT_CERT_ERROR",
        Some([
            "ошибка выбора сертификата",
            "Қолтаңба қою кезіндегі қателік",
            "ошибка выбора сертификата",
        ]),
    ),
    (
        "SIGN_XML_FAILED",
        Some([
            "ошибка подписания xml",
            "xml-ге қолтаңба қою кезіндегі қателік",
            "ошибка подписания xml",
        ]),
    ),
    (
        "SIGN_PLAIN_DATA_FAILED",
        Some([
            "ошибка подписания текста",
            "ошибка подписания текста",
            "ошибка подписания текста",
        ]),
    ),
    (
        "GET_FILE_FAILED",
        Some([
            "ошибка получения файла",
            "Мәтінге қол қою қатесі",
            "ошибка получения файла",
        ]),
    ),
    (
        "GET_HASH_FAILED",
        Some([
            "ошибка получения hash",
            "hash алу қатесі",
            "ошибка получения hash",
        ]),
    ),
    (
        "CREATE_CMS_ERROR",
        Some([
            "ошибка при формировании подписи",
            "Қолтаңбаны генерациялау кезіндегі қателік",
            "ошибка при формировании подписи",
        ]),
    ),
    (
        "NOT_VALID_URL",
        Some(["Не валидный URL", "Дұрыс емес URL", "Не валидный URL"]),
    ),
    (
        "FILE_NOT_FOUND",
        Some(["Файл не найден", "Файл табылмады", "Файл не найден"]),
    ),
    (
        "TYPE_NOT_SUPPORTED",
        Some([
            "Не потдержиываемый тип сообщения",
            "Қолдау көрсетілмейтін хабар түрі",
            "Не потдержиываемый тип сообщения",
        ]),
    ),
    (
        "WRONG_PASSWORD",
        Some(["Неверный пароль", "Қате құпиясөз", "Не верный пароль"]),
    ),
    (
        "DOWNLOAD_FILE_EXCEPTION",
        Some([
            "Ошибка при скачивании файла",
            "Файлды жүктеу қатесі",
            "Ошибка при скачивании файла",
        ]),
    ),
    (
        "EMPTY_STORAGE_NAME",
        Some([
            "Ошибка выбора сертификата",
            "Куәлік таңдау қатесі",
            "Ошибка выбора сертификата",
        ]),
    ),
    (
        "UNKNOW_STORAGE",
        Some([
            "Неизвестный источник сертификата",
            "Куәліктің белгісіз көзі",
            "Неизвестный источник сертификата",
        ]),
    ),
    (
        "CERTIFICATE_PARSING_ERROR",
        Some([
            "Ошибка при проверке сертификата",
            "Куәлікті тексеру қатесі",
            "Ошибка при проверке сертификата",
        ]),
    ),
    (
        "CREATE_REQUEST_ERROR",
        Some([
            "Ошибка при формировании запроса",
            "Сұрау салу кезінде қате",
            "Ошибка при формировании запроса",
        ]),
    ),
    (
        "REVOKED",
        Some([
            "Сертификат находится в списке отозванных сертификатов.",
            "Сертификат қайта шақыртылған сертификаттар тізімінде орналасқан.",
            "Certificate is revoked",
        ]),
    ),
    (
        "VALIDITY_EXPIRED",
        Some([
            "Период действия сертификата истек.",
            "Сертификаттың әрекет ету мерзімі аяқталды.",
            "Certificate validity period is expired",
        ]),
    ),
    (
        "NOT_YET_VALID",
        Some([
            "Период действия сертификата еще не наступил.",
            "Сертификаттың әрекет ету мерзімі басталған жоқ.",
            "Certificate not yet valid",
        ]),
    ),
    (
        "IIN_ABSENCE",
        Some([
            "В сертификате отсутствует ИИН (SERIALNUMBER в поле Subject).",
            "сертификатта ЖСН мәні жазылмаған(Subject бөліміндегі SERIALNUMBER өрісі).",
            "Certificate has no IIN field (SERIALNUMBER in field Subject).",
        ]),
    ),
    (
        "IIN_VALIDATION",
        Some([
            "Сертификат содержит неверное значение ИИН.",
            "Сертификаттағы ЖСН мәні қате.",
            "Certificate contains wrong IIN value",
        ]),
    ),
    (
        "BIN_VALIDATION",
        Some([
            "Сертификат содержит неверное значение БИН.",
            "Сертификаттағы БСН мәні қате.",
            "Certificate contains wrong BIN value",
        ]),
    ),
    (
        "BIN_ABSENCE",
        Some([
            "В сертификате отсутствует БИН (BIN в поле Subject).",
            "сертификатта БСН мәні жазылмаған(Subject бөліміндегі BIN өрісі).",
            "Certificate has no BIN field (BIN in field Subject).",
        ]),
    ),
    (
        "RNN_VALIDATION",
        Some([
            "Сертификат содержит неверное значение РНН",
            "Сертификатта СТН дұрыс емес мәні бар",
            "Сертификат содержит неверное значение РНН",
        ]),
    ),
    (
        "GU_DOES_NOT_EXISTS",
        Some([
            "В сертификате отстутствует код ГУ",
            "Сертификатта ММ коды жоқ",
            "В сертификате отстутствует код ГУ",
        ]),
    ),
    (
        "GU_NOT_IN_LIST",
        Some([
            "Код ГУ отсутствует в справочнике",
            "ММ коды анықтамалықта жоқ",
            "Код ГУ отсутствует в справочнике",
        ]),
    ),
    (
        "BIN_GU_CODE_NOT_CORRESPONDS",
        Some([
            "Код ГУ не соответствует БИН",
            "ММ коды БСН сәйкес келмейді",
            "Код ГУ не соответствует БИН",
        ]),
    ),
    (
        "RNN_GU_CODE_NOT_CORRESPONDS",
        Some([
            "Код ГУ не соответствует РНН",
            "ММ коды СТН сәйкес келмейді",
            "Код ГУ не соответствует РНН",
        ]),
    ),
    (
        "ROLE_DOES_NOT_EXISTS",
        Some([
            "В сертификате отстутствует роль",
            "Сертификатта рөл жоқ",
            "В сертификате отстутствует роль",
        ]),
    ),
    (
        "ROLE_NOT_IN_LIST",
        Some([
            "Роль отсутствует в справочнике",
            "Анықтамалықта рөл жоқ",
            "Роль отсутствует в справочнике",
        ]),
    ),
    ("MISSING_BIN", None),
    (
        "AUTH_DS_IIN_MISMATCH",
        Some([
            "ИИН в сертификатах аутентификации и ЭЦП не совпадают.",
            "Аутентификация мен электронды цифрлық қолтаңба сертификаттарындағы ЖСН сәйкес келмейді.",
            "The values of IIN field in authentication and digital signature certificates are mismatches",
        ]),
    ),
    (
        "AUTH_DS_GU_MISMATCH",
        Some([
            "Код ГУ в сертификатах аутентификации и ЭЦП не совпадают",
            "Аутентификация и ЭЦҚ сертификаттарында ММ коды сәйкес келмейді",
            "Код ГУ в сертификатах аутентификации и ЭЦП не совпадают",
        ]),
    ),
    (
        "AUTH_DS_ROLE_MISMATCH",
        Some([
            "Роль в сертификатах аутентификации и ЭЦП не совпадают",
            "Аутентификация и ЭЦҚ сертификаттарындағы рөл сәйкес келмейді",
            "Роль в сертификатах аутентификации и ЭЦП не совпадают",
        ]),
    ),
    (
        "AUTH_DS_BIN_MISMATCH",
        Some([
            "БИН в сертификатах аутентификации и ЭЦП не совпадают.",
            "Аутентификация мен электронды цифрлық қолтаңба сертификаттарындағы БСН сәйкес келмейді.",
            "The values of BIN field in authentication and digital signature certificates are mismatches",
        ]),
    ),
    (
        "FIRST_LAST_NAME_ABSENCE",
        Some([
            "В сертификате отсутствует ФИО (CN в поле Subject).",
            "Сертификатта Тегі мен Аты мәні жазылмаған(Subject бөліміндегі CN өрісі).",
            "Certificate has no name field (CN in field Subject).",
        ]),
    ),
    (
        "FIRST_LAST_NAME_VALIDATION",
        Some([
            "Поле, которое должно содержать фимилию и имя в сертификате, содержит только одно слово.",
            "Сертификатта Тегі мен Аты мәнін қамтитын өрісте тек қана бір сөз жазылған.",
            "The field, which should contain both first and last name, contains only one value",
        ]),
    ),
    (
        "SN_NOT_MATCHES_TO_CN",
        Some([
            "Значение фамилии в поле SN не совпадает со значением фамилии в поле CN!",
            "SN алабындағы тегі мәні SN алабындағы тегі мәніне сәйкес келмейді!",
            "Значение фамилии в поле SN не совпадает со значением фамилии в поле CN!",
        ]),
    ),
    (
        "CRL_FILE_NOT_FOUND",
        Some([
            "Не найден CRL файл",
            "CRL файл табылған жоқ",
            "Не найден CRL файл",
        ]),
    ),
    (
        "CRL_GENERATE_EXCEPTION",
        Some([
            "Ошибка генерации CRL",
            "CRL құру қатесі",
            "Ошибка генерации CRL",
        ]),
    ),
    (
        "CRL_URL_IS_EMPTY",
        Some(["Адрес CRL пустой", "CRL мекежайы бос", "Адрес CRL пустой"]),
    ),
    (
        "CRL_URL_IS_MALFORMED",
        Some([
            "Указан неверный адрес CRL",
            "CRL дұрыс емес мекенжайы көрсетілген",
            "Указан неверный адрес CRL",
        ]),
    ),
    (
        "CRL_DOWNLOAD_EXCEPTION",
        Some([
            "Ошибка скачивания CRL",
            "CRL жүктеу қатесі",
            "Ошибка скачивания CRL",
        ]),
    ),
    (
        "CRL_VERIFICATION_EXCEPTION",
        Some([
            "Подпись CRL не подлинна",
            "CRL қолы шынайы емес",
            "Подпись CRL не подлинна",
        ]),
    ),
    (
        "NO_CERT_FOR_CRL_VERIFICATION_EXCEPTION",
        Some([
            "Не найден сертификат для провеки подписи CRL",
            "CRL қолын тексеруге арналған сертификат табылмады",
            "Не найден сертификат для провеки подписи CRL",
        ]),
    ),
    (
        "BASE_CRL_NUMBER_IS_LESS_THEN_DELTA_CRL_BASE_NUMBER",
        Some([
            "Номер базового CRL меньше базового номера дельта CRL",
            "Негізгі CRL нөмірі негізгі дельта CRL нөмірінен аз",
            "Номер базового CRL меньше базового номера дельта CRL",
        ]),
    ),
    (
        "CERT_PATH_VALIDATION_EXCEPTION",
        Some([
            "Ошибка проверки пути сертификата. Сертификат выпущен не доверенным корневым УЦ",
            "Сертификат жолын тексеру қатесі. Сертификат сенімді емес негізгі КО шығарылған",
            "Ошибка проверки пути сертификата. Сертификат выпущен не доверенным корневым УЦ",
        ]),
    ),
    (
        "TC_OID_NOT_PRESENTED",
        Some([
            "Объектный идентификатор (OID) системы Комитета Казначейства не представлен в сертификате!",
            "Қазынашылық комитетінің объектілік идентификаторы (OID) сертификатта ұсынылмаған!",
            "Объектный идентификатор (OID) системы Комитета Казначейства не представлен в сертификате!",
        ]),
    ),
    (
        "TRUSTED_ANCHOR_LIST_IS_EMPTY",
        Some([
            "Список доверенных сертификатов не должен быть пустым. Обратитесь в службу тех. поддержки.",
            "Сенімді сертификаттардың тізімі бос болмауы керек. Тех. қолдау қызметімен байланысыңыз.",
            "Список доверенных сертификатов не должен быть пустым. Обратитесь в службу тех. поддержки.",
        ]),
    ),
    (
        "OCSP_REQUEST_ERROR",
        Some([
            "Ошибка OCSP запроса",
            "OCSP сұранымының қатесі",
            "Ошибка OCSP запроса",
        ]),
    ),
    (
        "OCSP_REVOKE_ERROR",
        Some([
            "Сертификат аннулирован",
            "Сертификат жойылған.",
            "Сертификат аннулирован",
        ]),
    ),
    (
        "OCSP_UNKNOWN_STATUS_ERROR",
        Some([
            "Сервер OCSP не может проверить статус данного сертификата",
            "OCSP сервері осы сертификаттың мәртебесін тексере алмайды.",
            "Сервер OCSP не может проверить статус данного сертификата",
        ]),
    ),
    (
        "OCSP_RESP_SIGN_CHECK_FAILED",
        Some([
            "Ошибка проверки подписи OCSP ответа",
            "жауаптың OCSP қолтаңбасын тескеру қатесі",
            "Ошибка проверки подписи OCSP ответа",
        ]),
    ),
    (
        "OCSP_RESP_SIGN_CERT_NOT_FOUND",
        Some([
            "Сертификат для проверки подписи OCSP ответа не найден",
            "жауаптың OCSP қолтаңбасын тескеру үшін сертификат табылған жоқ",
            "Сертификат для проверки подписи OCSP ответа не найден",
        ]),
    ),
    (
        "KEY_USAGE_NOT_PRESENTED",
        Some([
            "Назначение ключа не найдено в сертификате",
            "сертификатта кілтті тағайындау табылған жоқ",
            "Назначение ключа не найдено в сертификате",
        ]),
    ),
    (
        "DIGITAL_SIGNATURE_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Создание ЭЦП (digitalSignature)\"",
            "\"ЭЦҚ құру\" белгісі сертификатта жоқ (digitalSignature)\"",
            "В сертификате отсутствует признак \"Создание ЭЦП (digitalSignature)\"",
        ]),
    ),
    (
        "NON_REPUDIATION_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Неотрекаемость (nonRepudiation)\"",
            "\"Безінбеу (nonRepudiation)\" белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Неотрекаемость (nonRepudiation)\"",
        ]),
    ),
    (
        "KEY_ENCIPHERMENT_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Шифрование ключей (keyEncipherment)\"",
            "\"Кілттерді шифрлеу (keyEncipherment)\" белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Шифрование ключей (keyEncipherment)\"",
        ]),
    ),
    (
        "DATA_ENCIPHERMENT_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Шифрование данных (dataEncipherment)\"",
            "\"Деректерді шифрлау  (dataEncipherment)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Шифрование данных (dataEncipherment)\"",
        ]),
    ),
    (
        "KEY_AGREEMENT_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Обмен ключами (keyAgreement)\"",
            "\"Кілтермен алмасу (keyAgreement)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Обмен ключами (keyAgreement)\"",
        ]),
    ),
    (
        "KEY_CERT_SIGN_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Проверка подписи сертификатов (keyCertSignKey)\"",
            "\"Сертификаттардың қолтаңбасын тексеру (keyCertSignKey)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Проверка подписи сертификатов (keyCertSignKey)\"",
        ]),
    ),
    (
        "CRL_SIGN_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Проверка подписи CRL (cRLSign)\"",
            "\"Қолтаңбаны тексеру CRL (cRLSign)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Проверка подписи CRL (cRLSign)\"",
        ]),
    ),
    (
        "ENCIPHER_ONLY_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Только шифрование (encipherOnly)\"",
            "\"Тек қана шифрлау (encipherOnly)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Только шифрование (encipherOnly)\"",
        ]),
    ),
    (
        "DECIPHER_ONLY_KEY_USAGE_NOT_PRESENTED",
        Some([
            "В сертификате отсутствует признак \"Только дешифрование (decipherOnly)\"",
            "\"Тек қана шифрын анықтау (decipherOnly)\"белгісі сертификатта жоқ",
            "В сертификате отсутствует признак \"Только дешифрование (decipherOnly)\"",
        ]),
    ),
    ("BUNDLED_EXCEPTION", None),
    (
        "SIGN_VERIFICATION_FAILED",
        Some([
            "ЭЦП не подлинна!",
            "Қолтаңба түпнұсқа емес!",
            "Signature is invalid!",
        ]),
    ),
    (
        "SIGNINVALIDERROR",
        Some([
            "Ошибка при проверке ключа!",
            "Кілтті тексеру кезіндегі қате!",
            "Ошибка при проверке ключа!",
        ]),
    ),
    (
        "SIGN_VERIFICATION_SUCCESS",
        Some(["ЭЦП подлинна.", "Қолтаңба түпнұсқа!", "Signature is valid!"]),
    ),
    (
        "ALL_SIGN_ARE_VALID",
        Some([
            "Все ЭЦП подлинны.",
            "Барлық ЭЦҚ дәл.",
            "All signs are valid.",
        ]),
    ),
    (
        "ONE_NOT_VALID_SIGN_FOUND",
        Some([
            "Обнаружена не подлинная ЭЦП!",
            "Дәл емес ЭЦҚ анықталды!",
            "Not valid sign found!",
        ]),
    ),
    (
        "MANY_NOT_VALID_SIGN_FOUND",
        Some([
            "Обнаружены не подлинные ЭЦП!",
            "Дәл емес ЭЦҚ анықталды!",
            "Not valid signs found!",
        ]),
    ),
    (
        "UPLOAD_SIGN_VERIFY_RESULT_ERROR",
        Some([
            "Ошибка закачивания результатов проверки на серве",
            "Тексеру нәтижелерін серверге жүктеу қатесі",
            "Ошибка закачивания результатов проверки на серве",
        ]),
    ),
];

/// Texts of other keys a site's error type may name once upper-cased.
const OTHER_KEYS: &[(&str, [&str; 3])] = &[(
    "PKCS12",
    ["Файловая система", "Файлдық жүйе", "File system"],
)];

/// The error type named `name`, if K2Sign has one.
pub fn error_type(name: &str) -> Option<&'static str> {
    ERROR_TYPES
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(key, _)| *key)
}

/// The window text of the resource key `key` in `locale`: a single space if there is none.
pub fn text(key: &str, locale: Locale) -> &'static str {
    let texts = ERROR_TYPES
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, texts)| *texts)
        .or_else(|| OTHER_KEYS.iter().find(|(k, _)| *k == key).map(|(_, t)| *t));
    match texts {
        Some([ru, kk, en]) => match locale {
            Locale::Ru => ru,
            Locale::Kk => kk,
            Locale::En => en,
        },
        None => " ",
    }
}

/// Other texts of the windows.
pub struct Ui {
    /// The file dialog's title.
    pub open_file: &'static str,
    /// The name of its `*.pdf` filter.
    pub file: &'static str,
}

impl Ui {
    /// The texts of `locale`.
    pub fn of(locale: Locale) -> Ui {
        match locale {
            Locale::Ru | Locale::En => Ui {
                open_file: "Открыть файл",
                file: "Файл",
            },
            Locale::Kk => Ui {
                open_file: "Файлды ашу",
                file: "Құжат",
            },
        }
    }
}
