//! The methods of `CMSSignUtil`, reached through the dispatcher's `lang` variant.

use crate::texts::{Lang, Text};
use oncl_pdk::abi::{FileMode, Os, PageRead, PageWrite};
use oncl_pdk::files::{self, ChooseFileArgs};
use oncl_pdk::keys::{Action, CoSign, Filter, Key, KeyOrder};
use oncl_pdk::legacy::{
    self, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Request, host, keys};
use oncl_port_legacy::{
    CertProblem, Select, Storage, cades, cades_args, check_cert, file_filters, file_info,
    into_text, ok, response, select, split_path, storage,
};
use std::cell::Cell;

thread_local! {
    /// The language of the messages: the previous call's until `lang` of this one is read
    /// (the original keeps it for the process; here, for the session).
    static LANG: Cell<Lang> = const { Cell::new(Lang::Ru) };
}

fn lang() -> Lang {
    LANG.with(Cell::get)
}

fn text(t: Text) -> &'static str {
    t.get(lang())
}

/// The module's state lives in [`LANG`].
pub struct CmsSignUtil;

use LegacyBody::{Private, PrivateTakingObject, Public, Unconvertible};
use Param::Str;

const METHODS: &[LegacyMethod<CmsSignUtil>] = &[
    method("showKeyChooser", 1, Unconvertible),
    method("changeLang", 1, Public(&[Str], change_lang)),
    method("getDirectoryPath", 1, Public(&[Str], get_directory_path)),
    method("getFilePath", 2, Public(&[Str, Str], get_file_path)),
    method("signFilePath", 3, Public(&[Str, Str, Str], sign_file_path)),
    method("getMessage", 1, Public(&[Str], get_message)),
    method("verifyCMSResult", 1, Private),
    method("verifyCert", 3, Private),
    method("getMainException", 1, Private),
    method("sign", 2, Private),
    method("getStorageInfo", 1, Private),
    method("checkCert", 1, Private),
    method("saveFile", 3, Private),
    method("createCAdES", 4, Private),
    method("getFileFromPath", 1, Private),
    method("getFileFromPath", 2, Private),
    method("getDirectory", 1, Private),
    method("getOriginalFileName", 1, Private),
    method("getFreeFileName", 1, Private),
    method("createFileName", 2, Private),
    method("getJson", 1, PrivateTakingObject),
    method("getBytes", 1, Private),
    method("getListSignerInfo", 1, Private),
    method("fillSignerInfo", 2, Private),
    method("fillFromCert", 2, Private),
    method("getCaCertList", 0, Private),
    method("getCaCertsMap", 0, Private),
];

const fn method(
    name: &'static str,
    arity: usize,
    body: LegacyBody<CmsSignUtil>,
) -> LegacyMethod<CmsSignUtil> {
    LegacyMethod { name, arity, body }
}

const CLASS: LegacyClass<CmsSignUtil> = LegacyClass {
    dispatcher: "kz.gov.pki.cms.NLDocSignerActivator",
    target: "kz.gov.pki.cms.CMSSignUtil",
    methods: METHODS,
    error_bean: ErrorBean::ResponseForJs,
    no_such_method,
    before_invoke: Some(read_lang),
};

/// The plugin's handler.
pub fn handle(request: &Request) -> String {
    into_text(legacy::dispatch(
        &CmsSignUtil,
        &CLASS,
        &request.text,
        &request.add_info(),
    ))
}

/// The localized `NoSuchMethodException`, in the previous call's language.
fn no_such_method(_: &CmsSignUtil, name: &str) -> String {
    format!("{} {name}", text(Text::NoSuchMethod))
}

/// `changeLang(lang)` with the request's `lang`, right before the method runs.
fn read_lang(_: &CmsSignUtil, request: &Map<String, Value>) {
    let requested = orgjson::opt_string(request, "lang").unwrap_or_default();
    LANG.with(|l| l.set(Lang::of(&requested)));
}

fn failed(message: &str) -> Outcome {
    Outcome::Json(response(None, "500", Some(message)))
}

/// `changeLang(lang)`: a `void` method.
fn change_lang(_: &CmsSignUtil, args: &Args<'_>, _: &AddInfo) -> Outcome {
    LANG.with(|l| l.set(Lang::of(args.str(0))));
    Outcome::Null
}

/// `getMessage(key)`: the text, not JSON; a key the bundle lacks throws.
fn get_message(_: &CmsSignUtil, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match Text::of_key(args.str(0)) {
        Some(t) => Outcome::Text(text(t).to_owned()),
        None => Outcome::Thrown,
    }
}

/// The folder a chooser starts in: the page's, if it gave one.
fn initial(dir: &str) -> Option<String> {
    (!dir.is_empty()).then(|| dir.to_owned())
}

/// `getDirectoryPath(initialPath)`: `{"responseObject":<path>,"code":"200"}`, or
/// `{"code":"200"}` when cancelled.
fn get_directory_path(_: &CmsSignUtil, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Directory,
        title: Some(text(Text::DirChoose).to_owned()),
        filters: Vec::new(),
        initial_dir: initial(args.str(0)),
    });
    match chosen {
        Ok(Some(dir)) => ok(dir.path),
        Ok(None) => Outcome::Json(response(None, "200", None)),
        Err(_) => failed(text(Text::InternalError)),
    }
}

/// `getFilePath(fileExt, initialPath)`: the `FileInfo` of the chosen file, `{"size":0}` when
/// cancelled; an unknown `fileExt` throws.
fn get_file_path(_: &CmsSignUtil, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let Some(filters) = file_filters(args.str(0)) else {
        return Outcome::Thrown;
    };
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Open,
        title: Some(text(Text::KeyChoose).to_owned()),
        filters,
        initial_dir: initial(args.str(1)),
    });
    match chosen {
        Ok(Some(file)) => ok(file_info(&file.path, file.size.unwrap_or_default())),
        Ok(None) => {
            let mut empty = JObject::hash_map();
            empty.put("size", JValue::Int(0));
            ok(empty)
        }
        Err(_) => failed(text(Text::InternalError)),
    }
}

/// The local-path rule: a drive letter, a colon and a separator, on Windows only (network
/// drives and other paths a page may not name are the core's to refuse).
fn local(path: &str) -> bool {
    let b = path.trim_matches(|c| c <= ' ').as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
}

/// `signFilePath(filePath, fileDir, storageName)`: a CAdES-T of the file, attached, written
/// next to it as `<name>.cms` in `fileDir`.
fn sign_file_path(_: &CmsSignUtil, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match sign(args.str(0), args.str(1), args.str(2)) {
        Ok(path) => Outcome::Json(response(
            Some(JValue::from(path)),
            "200",
            Some(text(Text::CmsSigned)),
        )),
        Err(message) => failed(&message),
    }
}

fn sign(file_path: &str, file_dir: &str, storage_name: &str) -> Result<String, String> {
    let internal = || text(Text::InternalError).to_owned();
    // Unverified against the original: the drive checks are the core's page-path rules
    // (local or chosen network paths), and a missing folder shows when writing.
    let windows = host::platform().map_err(|_| internal())?.os == Os::Windows;
    if !windows || !local(file_path) || !local(file_dir) {
        return Err(internal());
    }
    let data = match files::page_read(file_path).map_err(|_| internal())? {
        PageRead::Ok(file) => file.data.into_vec(),
        PageRead::NotFound => return Err(text(Text::NonexistentPath).to_owned()),
        PageRead::TooLarge | PageRead::Declined => return Err(text(Text::FileIo).to_owned()),
    };
    if storage_name.trim_matches(|c| c <= ' ').is_empty() {
        return Err(text(Text::Required).to_owned());
    }
    let key = choose(storage_name)?;
    if let Some(problem) = check_cert(key.certificate()).map_err(|_| internal())? {
        return Err(text(problem_text(problem)).to_owned());
    }
    let args = cades_args(key.handle(), &data, true, CoSign::Auto, true);
    let cms = cades(&key, args)?;
    let (name, _) = split_path(file_path.trim_matches(|c| c <= ' '));
    let name = if name.ends_with(".cms") {
        name.to_owned()
    } else {
        format!("{name}.cms")
    };
    let io = || text(Text::FileIo).to_owned();
    match files::page_write(file_dir, &name, &cms).map_err(|_| io())? {
        PageWrite::Written(path) => Ok(path),
        // A name the folder cannot take: the original's fallback name.
        PageWrite::Invalid => match files::page_write(file_dir, "signedCMS.cms", &cms) {
            Ok(PageWrite::Written(path)) => Ok(path),
            _ => Err(io()),
        },
        PageWrite::Declined => Err(io()),
    }
}

/// The storage dialog of the module (the core's) and the key: signing keys only.
fn choose(storage_name: &str) -> Result<Key, String> {
    // Unverified against the original: storage names Kalkan does not know (an NPE there).
    let storage = storage(storage_name).map_err(|_| text(Text::InternalError).to_owned())?;
    if let Storage::Token(name) = storage
        && keys::terminals(name).map_or(true, |readers| readers.is_empty())
    {
        return Err("Носитель не обнаружен".to_owned());
    }
    let key = select(Select {
        storage: storage.name(),
        action: Action::Sign,
        knca_types: vec!["SIGNATURE".to_owned()],
        order: KeyOrder::NewestFirst,
        // The module checks the certificate itself.
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
    })
    .map_err(|_| text(Text::InternalError).to_owned())?;
    // One window of the core covers the original's storage window and key list: closing it
    // is the storage window's text.
    key.ok_or_else(|| "Не удалось открыть хранилище".to_owned())
}

/// The message of a refused certificate.
fn problem_text(problem: CertProblem) -> Text {
    match problem {
        CertProblem::NotSigning => Text::CertType,
        CertProblem::Expired => Text::CertExpired,
        CertProblem::NotYetValid => Text::CertNotYetValid,
        CertProblem::UnknownCa => Text::UnknownCa,
        CertProblem::Blocked => Text::CertVerification,
        CertProblem::Revoked => Text::OcspRevoked,
        CertProblem::OcspUnknown => Text::OcspUnknown,
        CertProblem::OcspNotVerified => Text::OcspNotVerified,
        CertProblem::OcspStale => Text::OcspException,
    }
}
