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
    /// XML: one element the plugin names (its XPath is the plugin's own text, framed apart:
    /// [`OperationConsent::xpaths`]).
    XmlElementFixed,
    /// XML: the element the user types in.
    XmlElementParam,
    /// XML: the signature goes into an element the plugin names (framed apart).
    XmlParentFixed,
    /// XML: the signature goes into an element the user types in.
    XmlParentParam,
    /// XML: where the signature is placed, when not at the end of the document element.
    XmlPlacement(PlacementKind),
    /// XML: this many namespace bindings of the plugin's XPaths.
    XmlNamespaces(usize),
    /// XML: an extra prefix/URI pair is set (the plugin's text; not shown).
    XmlOtherPrefixUri,
    /// The signature algorithm, a method URI of the core's known list.
    SignatureMethod(String),
    /// The digest algorithm, a method URI of the core's known list.
    DigestMethod(String),
    /// The canonicalisation, by the core's name for it.
    C14n(String),
    XmlStripWhitespace,
    /// The base64 of the signature has (`true`) or lacks line breaks.
    XmlBase64LineBreaks(bool),
    /// The output is re-serialised by the core.
    XmlSerialized,
    /// CMS: the content is signed as it is, even if it is a CMS itself (`cosign = never`).
    ContentAsIs,
    /// CMS: the output is not DER.
    CmsOutput(OutputForm),
    /// CMS: a signed attribute that is normally there is left out.
    AttributeOff(CmsAttribute),
    Xades(XadesLevelKind),
}

/// A non-DER output form of a CMS signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputForm {
    Base64,
    Pem,
}

/// A signed attribute of a CMS signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsAttribute {
    ContentType,
    MessageDigest,
    SigningCertificate,
}

/// Where an XML signature goes, when not at the end of the document element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementKind {
    FirstChildOfDocument,
    Parent,
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
    /// The XPaths its profile names (elements to sign, where the signature goes): free text
    /// of the manifest, untrusted, shown in the plugin's frame only.
    pub xpaths: Vec<String>,
}

/// Whether `name` is an operation identifier: `^[a-z][a-z0-9-]{0,31}$`. Checked at parse and
/// again where it is drawn.
pub fn is_operation_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
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
        ProfileFact::XmlElementFixed => o.xml_element_fixed.to_owned(),
        ProfileFact::XmlElementParam => o.xml_element_param.to_owned(),
        ProfileFact::XmlParentFixed => o.xml_parent_fixed.to_owned(),
        ProfileFact::XmlParentParam => o.xml_parent_param.to_owned(),
        ProfileFact::XmlPlacement(PlacementKind::FirstChildOfDocument) => {
            o.xml_placement_first.to_owned()
        }
        ProfileFact::XmlPlacement(PlacementKind::Parent) => o.xml_placement_parent.to_owned(),
        ProfileFact::XmlNamespaces(n) => o.xml_namespaces.replace("{0}", &n.to_string()),
        ProfileFact::XmlOtherPrefixUri => o.xml_other_prefix_uri.to_owned(),
        ProfileFact::SignatureMethod(m) => o.signature_method.replace("{0}", m),
        ProfileFact::DigestMethod(m) => o.digest_method.replace("{0}", m),
        ProfileFact::C14n(name) => o.c14n.replace("{0}", name),
        ProfileFact::XmlStripWhitespace => o.xml_strip.to_owned(),
        ProfileFact::XmlBase64LineBreaks(true) => o.b64_breaks_on.to_owned(),
        ProfileFact::XmlBase64LineBreaks(false) => o.b64_breaks_off.to_owned(),
        ProfileFact::XmlSerialized => o.xml_serialized.to_owned(),
        ProfileFact::ContentAsIs => o.content_as_is.to_owned(),
        ProfileFact::CmsOutput(OutputForm::Base64) => o.out_base64.to_owned(),
        ProfileFact::CmsOutput(OutputForm::Pem) => o.out_pem.to_owned(),
        ProfileFact::AttributeOff(CmsAttribute::ContentType) => o.off_content_type.to_owned(),
        ProfileFact::AttributeOff(CmsAttribute::MessageDigest) => o.off_message_digest.to_owned(),
        ProfileFact::AttributeOff(CmsAttribute::SigningCertificate) => {
            o.off_signing_cert.to_owned()
        }
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
    xml_element_fixed: &'static str,
    xml_element_param: &'static str,
    xml_parent_fixed: &'static str,
    xml_parent_param: &'static str,
    xml_placement_first: &'static str,
    xml_placement_parent: &'static str,
    /// `{0}`: how many.
    xml_namespaces: &'static str,
    xml_other_prefix_uri: &'static str,
    /// `{0}`: the method URI.
    signature_method: &'static str,
    /// `{0}`: the method URI.
    digest_method: &'static str,
    /// `{0}`: the core's name of the method.
    c14n: &'static str,
    xml_strip: &'static str,
    b64_breaks_on: &'static str,
    b64_breaks_off: &'static str,
    xml_serialized: &'static str,
    content_as_is: &'static str,
    out_base64: &'static str,
    out_pem: &'static str,
    off_content_type: &'static str,
    off_message_digest: &'static str,
    off_signing_cert: &'static str,
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
                key_raw: "кілтіңізбен қол қояды: мазмұнға өңделмеген қолтаңба",
                key_cms: "кілтіңізбен қол қояды: CMS (PKCS#7) қолтаңбасы",
                key_cms_ex: "кілтіңізбен қол қояды: кеңейтілген баптаулары бар CMS (PKCS#7) қолтаңбасы",
                key_xml: "кілтіңізбен қол қояды: XML қолтаңбасы (XMLDSig)",
                key_xml_ex: "кілтіңізбен қол қояды: кеңейтілген баптаулары бар XML қолтаңбасы (XMLDSig)",
                key_xades: "кілтіңізбен қол қояды: XAdES қолтаңбасы",
                profile: "қолтаңба түрі (өзек белгілейді): {0}",
                detached: "бөлек (мазмұн ішінде емес)",
                attached: "тіркелген (мазмұн ішінде)",
                digest_only: "құжаттың дайджестіне қол қойылады",
                no_timestamp: "уақыт таңбасыз",
                ts_basics: "basics TSA уақыт таңбасымен",
                ts_kalkan: "Kalkan-ның әдепкі TSA уақыт таңбасымен",
                chain: "кілттің сертификаттар тізбегімен",
                no_signing_time: "қол қою уақытынсыз",
                xml_whole: "бүкіл құжат",
                xml_element_param: "өзіңіз енгізетін элемент",
                xml_element_fixed: "плагин атаған бір элемент (оның XPath-ы төмендегі плагин жақтауында)",
                xml_parent_fixed: "қолтаңба плагин атаған элементке салынады (төмендегі жақтауда)",
                xml_parent_param: "қолтаңба өзіңіз енгізетін элементке салынады",
                xml_placement_first: "қолтаңба құжаттың бірінші түйінінің соңына салынады",
                xml_placement_parent: "қолтаңба таңдалған ата-ана элементінің соңына салынады",
                xml_namespaces: "XPath үшін аттар кеңістігінің байланыстары: {0}",
                xml_other_prefix_uri: "қосымша префикс/URI жұбы бар (плагиннің өз мәтіні)",
                signature_method: "қолтаңба алгоритмі: {0}",
                digest_method: "дайджест алгоритмі: {0}",
                c14n: "канонизация: {0}",
                xml_strip: "бос орындар алынып тасталады",
                b64_breaks_on: "base64 жол үзілістерімен",
                b64_breaks_off: "base64 жол үзілістерісіз",
                xml_serialized: "нәтижені өзек қайта сериализациялайды",
                content_as_is: "мазмұнға CMS болса да, сол күйінде қол қойылады",
                out_base64: "нәтиже DER емес, base64 түрінде",
                out_pem: "нәтиже DER емес, PEM түрінде",
                off_content_type: "contentType атрибуты жоқ",
                off_message_digest: "messageDigest атрибуты жоқ",
                off_signing_cert: "signingCertificateV2 атрибуты жоқ",
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
                xml_element_param: "элемент, который вы введёте",
                xml_element_fixed: "один элемент, который называет плагин (его XPath — в рамке плагина ниже)",
                xml_parent_fixed: "подпись кладётся в элемент, который называет плагин (в рамке ниже)",
                xml_parent_param: "подпись кладётся в элемент, который вы введёте",
                xml_placement_first: "подпись кладётся в конец первого узла документа",
                xml_placement_parent: "подпись кладётся в конец выбранного родительского элемента",
                xml_namespaces: "привязки пространств имён для XPath: {0}",
                xml_other_prefix_uri: "задана дополнительная пара префикс/URI (текст плагина)",
                signature_method: "алгоритм подписи: {0}",
                digest_method: "алгоритм дайджеста: {0}",
                c14n: "каноникализация: {0}",
                xml_strip: "пробельные символы убираются",
                b64_breaks_on: "base64 с переносами строк",
                b64_breaks_off: "base64 без переносов строк",
                xml_serialized: "результат заново сериализует ядро",
                content_as_is: "содержимое подписывается как есть, даже если это CMS",
                out_base64: "результат не DER, а base64",
                out_pem: "результат не DER, а PEM",
                off_content_type: "без атрибута contentType",
                off_message_digest: "без атрибута messageDigest",
                off_signing_cert: "без атрибута signingCertificateV2",
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
                xml_element_param: "the element you type in",
                xml_element_fixed: "one element the plugin names (its XPath is in the plugin's frame below)",
                xml_parent_fixed: "the signature goes into an element the plugin names (in the frame below)",
                xml_parent_param: "the signature goes into an element you type in",
                xml_placement_first: "the signature goes at the end of the document's first node",
                xml_placement_parent: "the signature goes at the end of the chosen parent element",
                xml_namespaces: "namespace bindings for the XPaths: {0}",
                xml_other_prefix_uri: "an extra prefix/URI pair is set (the plugin's own text)",
                signature_method: "signature algorithm: {0}",
                digest_method: "digest algorithm: {0}",
                c14n: "canonicalisation: {0}",
                xml_strip: "whitespace is stripped",
                b64_breaks_on: "base64 with line breaks",
                b64_breaks_off: "base64 without line breaks",
                xml_serialized: "the output is re-serialised by the core",
                content_as_is: "the content is signed as it is, even if it is a CMS",
                out_base64: "the output is base64, not DER",
                out_pem: "the output is PEM, not DER",
                off_content_type: "without the contentType attribute",
                off_message_digest: "without the messageDigest attribute",
                off_signing_cert: "without the signingCertificateV2 attribute",
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
                ProfileFact::XmlElementFixed,
                ProfileFact::XmlElementParam,
                ProfileFact::XmlParentFixed,
                ProfileFact::XmlParentParam,
                ProfileFact::XmlPlacement(PlacementKind::FirstChildOfDocument),
                ProfileFact::XmlPlacement(PlacementKind::Parent),
                ProfileFact::XmlNamespaces(2),
                ProfileFact::XmlOtherPrefixUri,
                ProfileFact::SignatureMethod("X1".to_owned()),
                ProfileFact::DigestMethod("X1".to_owned()),
                ProfileFact::C14n("X1".to_owned()),
                ProfileFact::XmlStripWhitespace,
                ProfileFact::XmlBase64LineBreaks(true),
                ProfileFact::XmlBase64LineBreaks(false),
                ProfileFact::XmlSerialized,
                ProfileFact::ContentAsIs,
                ProfileFact::CmsOutput(OutputForm::Base64),
                ProfileFact::CmsOutput(OutputForm::Pem),
                ProfileFact::AttributeOff(CmsAttribute::ContentType),
                ProfileFact::AttributeOff(CmsAttribute::MessageDigest),
                ProfileFact::AttributeOff(CmsAttribute::SigningCertificate),
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
    fn operation_names_are_checked_where_they_are_drawn() {
        assert!(is_operation_name("sign-file2"));
        assert!(is_operation_name(&"a".repeat(32)));
        for bad in [
            "",
            "Sign",
            "1a",
            "a_b",
            "a b",
            "а",
            "a\u{202E}",
            &"a".repeat(33),
            "-a",
        ] {
            assert!(!is_operation_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_consent_label_is_chosen_by_language() {
        let consent = OperationConsent {
            name: "sign-it".to_owned(),
            lines: Vec::new(),
            label: ["ру".to_owned(), "кк".to_owned(), "en".to_owned()],
            xpaths: Vec::new(),
        };
        assert_eq!(consent.label(Locale::Ru), "ру");
        assert_eq!(consent.label(Locale::Kk), "кк");
        assert_eq!(consent.label(Locale::En), "en");
    }
}
