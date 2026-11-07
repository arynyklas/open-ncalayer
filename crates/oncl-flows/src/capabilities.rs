//! What a plugin may do, said the same way by the install window and the project site:
//! [`CapabilityLine`] is one line, [`capability_text`] its words in a [`Locale`].

use crate::Locale;

/// What a plugin may do, a line each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityLine {
    /// Choose the user's key and sign with it.
    Keys,
    /// Show windows.
    Dialogs,
    /// Open and save files the user chooses.
    Files,
    /// Reach these URL prefixes.
    Http(Vec<String>),
    /// Reach the sites of these origins themselves (the page's own site).
    Origins(Vec<String>),
    /// Reach these plain-HTTP prefixes: an unprotected connection.
    HttpInsecure(Vec<String>),
    /// Open key store files the sites name, each once you allow it.
    KeyFiles,
    /// Read files and write into folders the sites name, each once you allow it; written
    /// files of these extensions.
    PageFiles(Vec<String>),
    /// Keep its settings on this computer.
    Settings,
    /// Share data between sites.
    Shared,
    /// Offer these operations (by name) in the manual-tools window, which may use your key,
    /// the network or more of the core than the installed version's.
    Operations(Vec<String>),
    /// An operation does not use the user's key.
    NoKey,
    /// An operation signs with the user's key: the kind of signature.
    KeyUse(KeyUseKind),
    /// The options the core forces on the signature of an operation ([`ProfileFact`]s).
    KeyProfile(Vec<ProfileFact>),
    /// The network an operation may reach.
    OperationNetwork(NetworkLine),
    /// Whether an operation is open to servers and the CLI (`true`) or to the manual window
    /// only.
    OperationServer(bool),
    /// An update: this is new or wider than the installed version's.
    Added(AddedLine),
}

/// The kind of signature an operation makes with the user's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUseKind {
    Raw,
    Cms,
    CmsEx,
    Xml,
    XmlEx,
    Xades,
}

/// The time-stamp authority family a profile fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsaFamily {
    Basics,
    Kalkan,
}

/// The XAdES level a profile fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XadesLevelKind {
    B,
    T,
    Lt,
}

/// One fact of the signing profile the core enforces on an operation, said in words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileFact {
    /// The content is not inside the signature.
    Detached,
    /// The content is inside the signature.
    Attached,
    /// The document's digest is signed, not its bytes.
    DigestOnly,
    NoTimestamp,
    Timestamp(TsaFamily),
    /// The key's certificate chain is included.
    ChainCertificates,
    NoSigningTime,
    /// XML: the whole document is signed.
    XmlWholeDocument,
    /// XML: this element (a validated XPath written in the manifest).
    XmlElement(String),
    /// XML: the element the user types in.
    XmlElementParam,
    Xades(XadesLevelKind),
}

/// The network of an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkLine {
    None,
    /// The PKI servers of the core only.
    Pki,
    /// These URL prefixes.
    Urls(Vec<String>),
}

/// Why an operation of an update counts as new or wider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddedLine {
    New,
    Changed,
    /// A new use of the key, or a changed profile.
    KeyUse,
    /// More host functions (their names).
    Imports(Vec<String>),
    Network,
    Server,
}

/// One operation as the install consent says it: every field in `lines` and `name` is
/// built by the host from checked data (`name` is a validated identifier); `label` is the
/// plugin's own text, to be shown framed as the plugin's and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationConsent {
    /// `^[a-z][a-z0-9-]{0,31}$`.
    pub name: String,
    /// The trusted lines.
    pub lines: Vec<CapabilityLine>,
    /// The plugin's label: Russian, Kazakh, English. Untrusted.
    pub label: [String; 3],
}

impl OperationConsent {
    /// The plugin's label in `l`: untrusted text.
    pub fn label(&self, l: Locale) -> &str {
        match l {
            Locale::Ru => &self.label[0],
            Locale::Kk => &self.label[1],
            Locale::En => &self.label[2],
        }
    }
}

/// What `capability` lets a plugin do, in `l`.
pub fn capability_text(capability: &CapabilityLine, l: Locale) -> String {
    let t = Texts::of(l);
    match capability {
        CapabilityLine::Keys => t.keys.to_owned(),
        CapabilityLine::Dialogs => t.dialogs.to_owned(),
        CapabilityLine::Files => t.files.to_owned(),
        CapabilityLine::Http(prefixes) => t.http.replace("{0}", &prefixes.join(", ")),
        CapabilityLine::Origins(origins) => t.origins.replace("{0}", &origins.join(", ")),
        CapabilityLine::HttpInsecure(prefixes) => {
            t.http_insecure.replace("{0}", &prefixes.join(", "))
        }
        CapabilityLine::KeyFiles => t.key_files.to_owned(),
        CapabilityLine::PageFiles(extensions) if extensions.is_empty() => {
            t.page_files_read.to_owned()
        }
        CapabilityLine::PageFiles(extensions) => t.page_files.replace(
            "{0}",
            &extensions
                .iter()
                .map(|e| format!(".{e}"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CapabilityLine::Settings => t.settings.to_owned(),
        CapabilityLine::Shared => t.shared.to_owned(),
        CapabilityLine::Operations(names) => t.operations.replace("{0}", &names.join(", ")),
        CapabilityLine::NoKey => OpTexts::of(l).no_key.to_owned(),
        CapabilityLine::KeyUse(kind) => {
            let o = OpTexts::of(l);
            match kind {
                KeyUseKind::Raw => o.key_raw,
                KeyUseKind::Cms => o.key_cms,
                KeyUseKind::CmsEx => o.key_cms_ex,
                KeyUseKind::Xml => o.key_xml,
                KeyUseKind::XmlEx => o.key_xml_ex,
                KeyUseKind::Xades => o.key_xades,
            }
            .to_owned()
        }
        CapabilityLine::KeyProfile(facts) => OpTexts::of(l).profile.replace(
            "{0}",
            &facts
                .iter()
                .map(|f| fact_text(f, l))
                .collect::<Vec<_>>()
                .join("; "),
        ),
        CapabilityLine::OperationNetwork(network) => {
            let o = OpTexts::of(l);
            match network {
                NetworkLine::None => o.net_none.to_owned(),
                NetworkLine::Pki => o.net_pki.to_owned(),
                NetworkLine::Urls(urls) => o.net_urls.replace("{0}", &urls.join(", ")),
            }
        }
        CapabilityLine::OperationServer(on) => {
            let o = OpTexts::of(l);
            if *on { o.server_on } else { o.server_off }.to_owned()
        }
        CapabilityLine::Added(added) => {
            let o = OpTexts::of(l);
            let why = match added {
                AddedLine::New => o.added_new.to_owned(),
                AddedLine::Changed => o.added_changed.to_owned(),
                AddedLine::KeyUse => o.added_key_use.to_owned(),
                AddedLine::Imports(names) => o.added_imports.replace("{0}", &names.join(", ")),
                AddedLine::Network => o.added_network.to_owned(),
                AddedLine::Server => o.added_server.to_owned(),
            };
            o.added.replace("{0}", &why)
        }
    }
}

fn fact_text(fact: &ProfileFact, l: Locale) -> String {
    let o = OpTexts::of(l);
    match fact {
        ProfileFact::Detached => o.detached.to_owned(),
        ProfileFact::Attached => o.attached.to_owned(),
        ProfileFact::DigestOnly => o.digest_only.to_owned(),
        ProfileFact::NoTimestamp => o.no_timestamp.to_owned(),
        ProfileFact::Timestamp(TsaFamily::Basics) => o.ts_basics.to_owned(),
        ProfileFact::Timestamp(TsaFamily::Kalkan) => o.ts_kalkan.to_owned(),
        ProfileFact::ChainCertificates => o.chain.to_owned(),
        ProfileFact::NoSigningTime => o.no_signing_time.to_owned(),
        ProfileFact::XmlWholeDocument => o.xml_whole.to_owned(),
        ProfileFact::XmlElement(xpath) => o.xml_element.replace("{0}", xpath),
        ProfileFact::XmlElementParam => o.xml_element_param.to_owned(),
        ProfileFact::Xades(XadesLevelKind::B) => o.xades_b.to_owned(),
        ProfileFact::Xades(XadesLevelKind::T) => o.xades_t.to_owned(),
        ProfileFact::Xades(XadesLevelKind::Lt) => o.xades_lt.to_owned(),
    }
}

/// The texts of an operation's lines, in one language. Every one is the host's own.
struct OpTexts {
    no_key: &'static str,
    key_raw: &'static str,
    key_cms: &'static str,
    key_cms_ex: &'static str,
    key_xml: &'static str,
    key_xml_ex: &'static str,
    key_xades: &'static str,
    /// `{0}`: the facts.
    profile: &'static str,
    detached: &'static str,
    attached: &'static str,
    digest_only: &'static str,
    no_timestamp: &'static str,
    ts_basics: &'static str,
    ts_kalkan: &'static str,
    chain: &'static str,
    no_signing_time: &'static str,
    xml_whole: &'static str,
    /// `{0}`: the XPath.
    xml_element: &'static str,
    xml_element_param: &'static str,
    xades_b: &'static str,
    xades_t: &'static str,
    xades_lt: &'static str,
    net_none: &'static str,
    net_pki: &'static str,
    /// `{0}`: the URL prefixes.
    net_urls: &'static str,
    server_on: &'static str,
    server_off: &'static str,
    /// `{0}`: one of the reasons below.
    added: &'static str,
    added_new: &'static str,
    added_changed: &'static str,
    added_key_use: &'static str,
    /// `{0}`: the host functions.
    added_imports: &'static str,
    added_network: &'static str,
    added_server: &'static str,
}

impl OpTexts {
    fn of(l: Locale) -> &'static OpTexts {
        match l {
            Locale::Kk => &OpTexts {
                no_key: "сіздің кілтіңізді пайдаланбайды",
                key_raw: "кілтіңізбен қол қояды: мазмұнға шикі қолтаңба",
                key_cms: "кілтіңізбен қол қояды: CMS (PKCS#7) қолтаңбасы",
                key_cms_ex: "кілтіңізбен қол қояды: кеңейтілген баптаулары бар CMS (PKCS#7) қолтаңбасы",
                key_xml: "кілтіңізбен қол қояды: XML қолтаңбасы (XMLDSig)",
                key_xml_ex: "кілтіңізбен қол қояды: кеңейтілген баптаулары бар XML қолтаңбасы (XMLDSig)",
                key_xades: "кілтіңізбен қол қояды: XAdES қолтаңбасы",
                profile: "қолтаңба түрі (өзек белгілейді): {0}",
                detached: "бөлек (мазмұн ішінде емес)",
                attached: "тіркелген (мазмұн ішінде)",
                digest_only: "құжаттың хэшіне қол қойылады",
                no_timestamp: "уақыт таңбасыз",
                ts_basics: "basics TSA уақыт таңбасымен",
                ts_kalkan: "Kalkan-ның әдепкі TSA уақыт таңбасымен",
                chain: "кілттің сертификаттар тізбегімен",
                no_signing_time: "қол қою уақытынсыз",
                xml_whole: "бүкіл құжат",
                xml_element: "{0} элементі",
                xml_element_param: "өзіңіз енгізетін элемент",
                xades_b: "XAdES, B деңгейі",
                xades_t: "XAdES, T деңгейі",
                xades_lt: "XAdES, LT деңгейі",
                net_none: "желісіз",
                net_pki: "желі: тек өзектің PKI серверлері",
                net_urls: "желі: {0}",
                server_on: "серверлер мен CLI үшін де қолжетімді",
                server_off: "тек қолмен жұмыс терезесі (серверлер мен CLI үшін емес)",
                added: "ЖАҢА немесе КЕҢІРЕК: {0}",
                added_new: "жаңа әрекет",
                added_changed: "әрекет өзгерді",
                added_key_use: "кілтіңізді жаңа пайдалану немесе өзгерген қолтаңба түрі",
                added_imports: "өзектің көбірек функциялары: {0}",
                added_network: "кеңірек желі",
                added_server: "енді серверлер мен CLI үшін қолжетімді",
            },
            Locale::Ru => &OpTexts {
                no_key: "не использует ваш ключ",
                key_raw: "подписывает вашим ключом: «сырая» подпись содержимого",
                key_cms: "подписывает вашим ключом: подпись CMS (PKCS#7)",
                key_cms_ex: "подписывает вашим ключом: подпись CMS (PKCS#7) с расширенными параметрами",
                key_xml: "подписывает вашим ключом: подпись XML (XMLDSig)",
                key_xml_ex: "подписывает вашим ключом: подпись XML (XMLDSig) с расширенными параметрами",
                key_xades: "подписывает вашим ключом: подпись XAdES",
                profile: "вид подписи (задаёт ядро): {0}",
                detached: "отделённая (содержимое не внутри)",
                attached: "присоединённая (содержимое внутри)",
                digest_only: "подписывается хеш документа",
                no_timestamp: "без штампа времени",
                ts_basics: "со штампом времени TSA basics",
                ts_kalkan: "со штампом времени TSA Kalkan по умолчанию",
                chain: "с цепочкой сертификатов ключа",
                no_signing_time: "без времени подписания",
                xml_whole: "весь документ",
                xml_element: "элемент {0}",
                xml_element_param: "элемент, который вы введёте",
                xades_b: "XAdES, уровень B",
                xades_t: "XAdES, уровень T",
                xades_lt: "XAdES, уровень LT",
                net_none: "без сети",
                net_pki: "сеть: только PKI-серверы ядра",
                net_urls: "сеть: {0}",
                server_on: "доступно также серверам и CLI",
                server_off: "только ручное окно (не для серверов и CLI)",
                added: "НОВОЕ или ШИРЕ: {0}",
                added_new: "новая операция",
                added_changed: "операция изменилась",
                added_key_use: "новое использование вашего ключа или изменённый вид подписи",
                added_imports: "больше функций ядра: {0}",
                added_network: "более широкая сеть",
                added_server: "теперь доступно серверам и CLI",
            },
            Locale::En => &OpTexts {
                no_key: "does not use your key",
                key_raw: "signs with your key: a raw signature of the content",
                key_cms: "signs with your key: a CMS (PKCS#7) signature",
                key_cms_ex: "signs with your key: a CMS (PKCS#7) signature with extended options",
                key_xml: "signs with your key: an XML signature (XMLDSig)",
                key_xml_ex: "signs with your key: an XML signature (XMLDSig) with extended options",
                key_xades: "signs with your key: a XAdES signature",
                profile: "signature form (fixed by the core): {0}",
                detached: "detached (the content is not inside)",
                attached: "attached (the content is inside)",
                digest_only: "the document's digest is signed",
                no_timestamp: "no time-stamp",
                ts_basics: "time-stamp from the basics TSA",
                ts_kalkan: "time-stamp from Kalkan's default TSA",
                chain: "with the key's certificate chain",
                no_signing_time: "no signing time",
                xml_whole: "the whole document",
                xml_element: "the element {0}",
                xml_element_param: "the element you type in",
                xades_b: "XAdES level B",
                xades_t: "XAdES level T",
                xades_lt: "XAdES level LT",
                net_none: "no network",
                net_pki: "network: the PKI servers of the core only",
                net_urls: "network: {0}",
                server_on: "also available to servers and the CLI",
                server_off: "the manual window only (not for servers or the CLI)",
                added: "NEW or WIDER: {0}",
                added_new: "a new operation",
                added_changed: "the operation changed",
                added_key_use: "a new use of your key or a changed signature profile",
                added_imports: "more core functions: {0}",
                added_network: "a wider network",
                added_server: "newly available to servers and the CLI",
            },
        }
    }
}

/// The capability texts, in one language.
struct Texts {
    keys: &'static str,
    dialogs: &'static str,
    files: &'static str,
    /// `{0}`: the URL prefixes.
    http: &'static str,
    /// `{0}`: the origin patterns.
    origins: &'static str,
    /// `{0}`: the plain-HTTP prefixes.
    http_insecure: &'static str,
    key_files: &'static str,
    page_files_read: &'static str,
    /// `{0}`: the extensions written.
    page_files: &'static str,
    settings: &'static str,
    shared: &'static str,
    /// `{0}`: the operation names.
    operations: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                keys: "кілтіңізді таңдау және онымен қол қою",
                dialogs: "терезелерді көрсету",
                files: "өзіңіз таңдаған файлдарды ашу және сақтау",
                http: "мына мекенжайларға жүгіну: {0}",
                origins: "мына сайттардың өздеріне жүгіну: {0}",
                http_insecure: "қорғалмаған байланыс арқылы жүгіну: {0}",
                key_files: "сайттар атаған кілт файлдарын ашу, әрқайсысын сіз рұқсат еткеннен кейін",
                page_files_read: "сайттар атаған файлдарды оқу, әрқайсысын сіз рұқсат еткеннен кейін",
                page_files: "сайттар атаған файлдарды оқу және папкаларға {0} файлдарын жазу, әрқайсысын сіз рұқсат еткеннен кейін",
                settings: "баптауларын осы компьютерде сақтау",
                shared: "деректерді сайттар арасында бөлісу",
                operations: "қолмен жұмыс терезесінде кілтіңізді, желіні немесе өзекті кеңірек пайдалана алатын әрекеттерді ұсыну: {0}",
            },
            Locale::Ru => &Texts {
                keys: "выбирать ваш ключ и подписывать им",
                dialogs: "показывать окна",
                files: "открывать и сохранять файлы, которые вы выберете",
                http: "обращаться к {0}",
                origins: "обращаться к самим сайтам {0}",
                http_insecure: "обращаться по незащищённому соединению к {0}",
                key_files: "открывать файлы ключей, которые назовут сайты, — каждый после вашего разрешения",
                page_files_read: "читать файлы, которые назовут сайты, — каждый после вашего разрешения",
                page_files: "читать файлы и записывать файлы {0} в папки, которые назовут сайты, — каждый файл и каждую папку после вашего разрешения",
                settings: "хранить свои настройки на этом компьютере",
                shared: "делить данные между сайтами",
                operations: "предлагать в окне ручных инструментов действия, которые могут использовать ваш ключ, сеть или больше возможностей ядра: {0}",
            },
            Locale::En => &Texts {
                keys: "choose your key and sign with it",
                dialogs: "show windows",
                files: "open and save files you choose",
                http: "reach {0}",
                origins: "reach the sites {0} themselves",
                http_insecure: "reach {0} over an unprotected connection",
                key_files: "open key files the sites name, each once you allow it",
                page_files_read: "read files the sites name, each once you allow it",
                page_files: "read files and write {0} files into folders the sites name, each once you allow it",
                settings: "keep its settings on this computer",
                shared: "share data between sites",
                operations: "offer in the manual-tools window operations that may use your key, the network or more of the core: {0}",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_files_say_when_permission_is_asked() {
        let page_files = CapabilityLine::PageFiles(vec!["xml".to_owned(), "pdf".to_owned()]);
        assert_eq!(
            capability_text(&page_files, Locale::Ru),
            "читать файлы и записывать файлы .xml, .pdf в папки, которые назовут сайты, — \
             каждый файл и каждую папку после вашего разрешения"
        );
        assert_eq!(
            capability_text(&page_files, Locale::En),
            "read files and write .xml, .pdf files into folders the sites name, each once you \
             allow it"
        );
    }

    #[test]
    fn capability_texts_exist_in_every_locale() {
        let list = || vec!["X1".to_owned()];
        let every = [
            CapabilityLine::Keys,
            CapabilityLine::Dialogs,
            CapabilityLine::Files,
            CapabilityLine::Http(list()),
            CapabilityLine::Origins(list()),
            CapabilityLine::HttpInsecure(list()),
            CapabilityLine::KeyFiles,
            CapabilityLine::PageFiles(Vec::new()),
            CapabilityLine::PageFiles(list()),
            CapabilityLine::Settings,
            CapabilityLine::Shared,
            CapabilityLine::Operations(list()),
        ];
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            for c in &every {
                let text = capability_text(c, l);
                assert!(!text.trim().is_empty(), "{c:?} {l:?}");
                assert!(!text.contains("{0}"), "{c:?} {l:?}: {text}");
                if matches!(
                    c,
                    CapabilityLine::Http(_)
                        | CapabilityLine::Origins(_)
                        | CapabilityLine::HttpInsecure(_)
                        | CapabilityLine::PageFiles(_)
                        | CapabilityLine::Operations(_)
                ) && c != &CapabilityLine::PageFiles(Vec::new())
                {
                    assert!(text.contains("X1"), "{c:?} {l:?}: {text}");
                }
            }
        }
    }

    #[test]
    fn operation_texts_exist_distinct_in_every_locale() {
        let list = || vec!["X1".to_owned()];
        let every = [
            CapabilityLine::NoKey,
            CapabilityLine::KeyUse(KeyUseKind::Raw),
            CapabilityLine::KeyUse(KeyUseKind::Cms),
            CapabilityLine::KeyUse(KeyUseKind::CmsEx),
            CapabilityLine::KeyUse(KeyUseKind::Xml),
            CapabilityLine::KeyUse(KeyUseKind::XmlEx),
            CapabilityLine::KeyUse(KeyUseKind::Xades),
            CapabilityLine::KeyProfile(vec![
                ProfileFact::Detached,
                ProfileFact::Attached,
                ProfileFact::DigestOnly,
                ProfileFact::NoTimestamp,
                ProfileFact::Timestamp(TsaFamily::Basics),
                ProfileFact::Timestamp(TsaFamily::Kalkan),
                ProfileFact::ChainCertificates,
                ProfileFact::NoSigningTime,
                ProfileFact::XmlWholeDocument,
                ProfileFact::XmlElement("/X1".to_owned()),
                ProfileFact::XmlElementParam,
                ProfileFact::Xades(XadesLevelKind::B),
                ProfileFact::Xades(XadesLevelKind::T),
                ProfileFact::Xades(XadesLevelKind::Lt),
            ]),
            CapabilityLine::OperationNetwork(NetworkLine::None),
            CapabilityLine::OperationNetwork(NetworkLine::Pki),
            CapabilityLine::OperationNetwork(NetworkLine::Urls(list())),
            CapabilityLine::OperationServer(true),
            CapabilityLine::OperationServer(false),
            CapabilityLine::Added(AddedLine::New),
            CapabilityLine::Added(AddedLine::Changed),
            CapabilityLine::Added(AddedLine::KeyUse),
            CapabilityLine::Added(AddedLine::Imports(list())),
            CapabilityLine::Added(AddedLine::Network),
            CapabilityLine::Added(AddedLine::Server),
        ];
        for c in &every {
            let ru = capability_text(c, Locale::Ru);
            let kk = capability_text(c, Locale::Kk);
            let en = capability_text(c, Locale::En);
            for (l, text) in [(Locale::Ru, &ru), (Locale::Kk, &kk), (Locale::En, &en)] {
                assert!(!text.trim().is_empty(), "{c:?} {l:?}");
                assert!(!text.contains("{0}"), "{c:?} {l:?}: {text}");
            }
            assert!(
                ru != kk && ru != en && kk != en,
                "{c:?}: {ru} | {kk} | {en}"
            );
        }
        // The profile's facts, one by one, are distinct and non-empty too.
        let CapabilityLine::KeyProfile(facts) = &every[7] else {
            unreachable!()
        };
        for fact in facts {
            let one = CapabilityLine::KeyProfile(vec![fact.clone()]);
            let (ru, kk, en) = (
                capability_text(&one, Locale::Ru),
                capability_text(&one, Locale::Kk),
                capability_text(&one, Locale::En),
            );
            assert!(ru != kk && ru != en && kk != en, "{fact:?}");
        }
    }

    #[test]
    fn operation_lines_name_what_the_core_enforces() {
        let line = CapabilityLine::KeyProfile(vec![
            ProfileFact::Attached,
            ProfileFact::Timestamp(TsaFamily::Kalkan),
        ]);
        let en = capability_text(&line, Locale::En);
        assert!(en.contains("attached") && en.contains("Kalkan"), "{en}");
        assert_eq!(
            capability_text(
                &CapabilityLine::OperationNetwork(NetworkLine::Pki),
                Locale::En
            ),
            "network: the PKI servers of the core only"
        );
        assert_eq!(
            capability_text(&CapabilityLine::Added(AddedLine::Server), Locale::En),
            "NEW or WIDER: newly available to servers and the CLI"
        );
    }

    #[test]
    fn a_consent_label_is_chosen_by_language() {
        let consent = OperationConsent {
            name: "sign-it".to_owned(),
            lines: Vec::new(),
            label: ["ру".to_owned(), "кк".to_owned(), "en".to_owned()],
        };
        assert_eq!(consent.label(Locale::Ru), "ру");
        assert_eq!(consent.label(Locale::Kk), "кк");
        assert_eq!(consent.label(Locale::En), "en");
    }
}
