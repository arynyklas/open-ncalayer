//! `[[operations]]` of `plugin.toml`: what parses, what is refused and why, the canonical
//! encoding of a profile, and what an update adds. The reference text is the design,
//! `docs/design/manual-plugins.md` section 4.1.

mod common;

use oncl_pdk::abi::Import;
use oncl_plugin::operations::{
    Content, KeyKind, Network, OperationError, Profile, Source, Timestamp, operations_min_core,
};
use oncl_plugin::{Engine, LoadError, Manifest, PackageError};
use sha2::{Digest, Sha256};

const HEAD: &str = r#"
id = "kz.example.sign"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["example.sign", "example.other"]

[name]
ru = "Подпись"
kk = "Қол қою"
en = "Sign"

[capabilities]
keys = true
http = ["https://api.example.kz/"]
"#;

/// The reference operation: the design's example, completed.
const OP: &str = r#"
[[operations]]
name    = "sign-file"
module  = "example.sign"
manual  = true
server  = false
request = '{"module":"example.sign","method":"signFile","args":["{file:base64}"]}'
label   = { ru = "Подписать файл", kk = "Файлға қол қою", en = "Sign a file" }

[[operations.params]]
name = "file"
kind = "document"
max_bytes = 16777216

[operations.uses]
imports = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"]
network = "pki"
interactive = ["keys_select"]

[[operations.uses.key]]
kind     = "cms_ex"
content  = "param:file"
max_uses = 1
[operations.uses.key.profile]
encapsulate  = false
cosign       = "never"
timestamp    = "basics"
certificates = "signer"
output       = "der"
"#;

fn parse(text: &str) -> Result<Manifest, PackageError> {
    Manifest::from_toml(text)
}

fn with(op: &str) -> String {
    format!("{HEAD}{op}")
}

/// `OP` with `from` replaced by `to`; it must be there.
fn edit(from: &str, to: &str) -> String {
    assert!(
        OP.contains(from),
        "{from:?} is not in the reference operation"
    );
    with(&OP.replacen(from, to, 1))
}

fn refused(text: &str) -> OperationError {
    match parse(text) {
        Err(PackageError::Operation(e)) => e,
        other => panic!("expected an operation error, got {other:?}"),
    }
}

/// The text of a refusal of the TOML layer (an unknown key, a bad type) or of a profile
/// (whose own unknown keys are refused when the kind is known).
fn refused_toml(text: &str) -> String {
    match parse(text) {
        Err(PackageError::Manifest(e)) => e,
        Err(PackageError::Operation(OperationError::Profile { why, .. })) => why,
        other => panic!("expected a manifest error, got {other:?}"),
    }
}

#[test]
fn the_reference_operation_parses_with_every_field() {
    let manifest = parse(&with(OP)).unwrap();
    let [op] = manifest.operations() else {
        panic!("one operation")
    };
    assert_eq!(op.name(), "sign-file");
    assert_eq!(op.module(), "example.sign");
    assert!(op.manual() && !op.server());
    assert_eq!(op.label().en, "Sign a file");
    assert_eq!(op.params().len(), 1);
    assert_eq!(op.uses().network(), &Network::Pki);
    assert_eq!(
        op.uses().imports(),
        [
            Import::KeysSelect,
            Import::KeysDescribe,
            Import::KeysSignCmsEx,
            Import::Hash
        ]
    );
    assert_eq!(op.uses().interactive(), [Import::KeysSelect]);
    let [key] = op.uses().keys() else {
        panic!("one key use")
    };
    assert_eq!(key.kind(), KeyKind::CmsEx);
    assert_eq!(key.content(), &Content::Bound("file".to_owned()));
    assert_eq!(key.max_uses(), 1);
    let Profile::CmsEx(p) = key.profile() else {
        panic!("a cms_ex profile")
    };
    assert_eq!(p.timestamp, Timestamp::Basics);
    assert!(op.runnable() && !op.is_derived());
}

#[test]
fn a_manifest_without_operations_has_none() {
    let manifest = parse(HEAD).unwrap();
    assert!(manifest.operations().is_empty());
}

#[test]
fn every_shipped_manifest_parses_and_declares_no_operations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let mut count = 0;
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path().join("plugin.toml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let manifest = Manifest::from_toml(&text)
            .unwrap_or_else(|e| panic!("{} no longer parses: {e}", path.display()));
        assert!(
            manifest.operations().is_empty(),
            "{} declares operations",
            path.display()
        );
        count += 1;
    }
    assert!(count >= 34, "only {count} manifests found");
}

#[test]
fn derived_content_parses_but_is_not_runnable() {
    let manifest = parse(&edit(
        r#"content  = "param:file""#,
        r#"content  = "derived""#,
    ))
    .unwrap();
    let op = &manifest.operations()[0];
    assert!(op.is_derived());
    assert!(!op.runnable(), "the host must refuse derived until MP3b");
    assert_eq!(op.uses().keys()[0].content(), &Content::Derived);
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    for (from, to, key) in [
        (r#"manual  = true"#, "manual = true\nextra = 1", "extra"),
        (
            r#"network = "pki""#,
            "network = \"pki\"\nwide = true",
            "wide",
        ),
        (r#"max_uses = 1"#, "max_uses = 1\nshared = true", "shared"),
        (
            r#"output       = "der""#,
            "output = \"der\"\nattrs = { extra = [] }",
            "attrs",
        ),
        ("max_bytes = 16777216", "max_bytes = 5\nmax = 9", "max"),
    ] {
        let e = refused_toml(&edit(from, to));
        assert!(e.contains("unknown field") && e.contains(key), "{key}: {e}");
    }
}

#[test]
fn profile_fields_outside_the_whitelist_are_refused() {
    // Each is a signature option the plugin must not be able to choose.
    for (field, wanted) in [
        (r#"cosign = "auto""#, "cosign"),
        (r#"timestamp = "custom""#, "timestamp"),
        ("econtent_type = \"1.2.3\"", "econtent_type"),
        ("extra = [{ oid = \"1.2.3\", values = [] }]", "extra"),
        (r#"certificates = "extra""#, "certificates"),
        ("digest = \"sha256\"", "digest"),
    ] {
        let text = edit(
            "[operations.uses.key.profile]\n",
            &format!("[operations.uses.key.profile]\n{field}\n"),
        );
        // `timestamp` and `cosign` are set again below the inserted line: drop them.
        let text = text
            .replace("cosign       = \"never\"\n", "")
            .replace("timestamp    = \"basics\"\n", "")
            .replace("certificates = \"signer\"\n", "");
        let e = match parse(&text) {
            Err(PackageError::Operation(OperationError::Profile { why, .. })) => why,
            other => panic!("{field}: {other:?}"),
        };
        assert!(e.contains(wanted), "{field}: {e}");
    }
}

#[test]
fn the_refusal_matrix() {
    use OperationError as E;
    type Check = fn(&E) -> bool;
    let cases: Vec<(&str, String, Check)> = vec![
        (
            "duplicate name",
            with(&format!("{OP}{OP}")),
            |e| matches!(e, E::DuplicateName(n) if n == "sign-file"),
        ),
        (
            "empty name",
            edit(r#"name    = "sign-file""#, r#"name    = """#),
            |e| matches!(e, E::Name(_)),
        ),
        (
            "uppercase name",
            edit(r#"name    = "sign-file""#, r#"name    = "Sign""#),
            |e| matches!(e, E::Name(_)),
        ),
        (
            "long name",
            edit(
                r#"name    = "sign-file""#,
                &format!(r#"name    = "a{}""#, "b".repeat(32)),
            ),
            |e| matches!(e, E::Name(_)),
        ),
        (
            "module not served",
            edit(r#"module  = "example.sign""#, r#"module  = "example.x""#),
            |e| matches!(e, E::Module { .. }),
        ),
        (
            "offered nowhere",
            edit("manual  = true", "manual  = false"),
            |e| matches!(e, E::NotOffered(_)),
        ),
        (
            "blank label",
            edit(r#"en = "Sign a file""#, r#"en = "  ""#),
            |e| matches!(e, E::Label { lang: "en", .. }),
        ),
        (
            "long label",
            edit(
                r#"en = "Sign a file""#,
                &format!(r#"en = "{}""#, "x".repeat(81)),
            ),
            |e| matches!(e, E::Label { .. }),
        ),
        (
            "control character in label",
            edit(r#"en = "Sign a file""#, r#"en = "Sign\u0007 a file""#),
            |e| matches!(e, E::Label { .. }),
        ),
        (
            "bidi character in label",
            edit(r#"en = "Sign a file""#, r#"en = "Sign\u202E a file""#),
            |e| matches!(e, E::Label { .. }),
        ),
        (
            "max_uses 2",
            edit("max_uses = 1", "max_uses = 2"),
            |e| matches!(e, E::KeyContent { why, .. } if why.contains("max_uses")),
        ),
        (
            "max_uses 0",
            edit("max_uses = 1", "max_uses = 0"),
            |e| matches!(e, E::KeyContent { why, .. } if why.contains("max_uses")),
        ),
        (
            "content spelled wrong",
            edit(r#"content  = "param:file""#, r#"content  = "file""#),
            |e| matches!(e, E::KeyContent { .. }),
        ),
        (
            "content of an undeclared param",
            edit(r#"content  = "param:file""#, r#"content  = "param:other""#),
            |e| matches!(e, E::KeyContent { .. }),
        ),
        (
            "raw over derived",
            edit(r#"content  = "param:file""#, r#"content  = "derived""#).replace("cms_ex", "raw"),
            // the profile of cms_ex is not a raw profile either; the content rule comes first
            |e| {
                matches!(e, E::KeyContent { why, .. } if why.contains("raw"))
                    || matches!(e, E::KeyUse { .. })
            },
        ),
        (
            "digest over derived",
            edit(r#"content  = "param:file""#, r#"content  = "derived""#)
                .replace("encapsulate  = false", "content_form = \"digest\""),
            |e| matches!(e, E::KeyContent { why, .. } if why.contains("digest")),
        ),
        (
            "encapsulated digest",
            edit(
                "encapsulate  = false",
                "content_form = \"digest\"\nencapsulate = true",
            ),
            |e| matches!(e, E::Profile { why, .. } if why.contains("encapsulated")),
        ),
        (
            "unknown import",
            edit(r#""hash"]"#, r#""no_such_function"]"#),
            |e| matches!(e, E::UnknownImport { .. }),
        ),
        (
            "dialog import",
            edit(r#""hash"]"#, r#""hash", "dialog_message"]"#),
            |e| {
                matches!(
                    e,
                    E::ForbiddenImport {
                        name: "dialog_message",
                        ..
                    }
                )
            },
        ),
        (
            "file import",
            edit(r#""hash"]"#, r#""hash", "file_open"]"#),
            |e| matches!(e, E::ForbiddenImport { .. }),
        ),
        (
            "open-window import",
            edit(r#""hash"]"#, r#""hash", "core_open_window"]"#),
            |e| matches!(e, E::ForbiddenImport { .. }),
        ),
        (
            "keys_open import",
            edit(r#""hash"]"#, r#""hash", "keys_open"]"#),
            |e| {
                matches!(
                    e,
                    E::ForbiddenImport {
                        name: "keys_open",
                        ..
                    }
                )
            },
        ),
        (
            "undeclared capability",
            edit(r#""hash"]"#, r#""hash", "settings_get"]"#),
            |e| {
                matches!(
                    e,
                    E::UndeclaredImport {
                        name: "settings_get",
                        ..
                    }
                )
            },
        ),
        (
            "duplicate import",
            edit(r#""hash"]"#, r#""hash", "hash"]"#),
            |e| matches!(e, E::DuplicateImport { .. }),
        ),
        (
            "interactive outside the key choice",
            edit(
                r#"interactive = ["keys_select"]"#,
                r#"interactive = ["hash"]"#,
            ),
            |e| matches!(e, E::Interactive { .. }),
        ),
        (
            "interactive not imported",
            edit(
                r#"interactive = ["keys_select"]"#,
                r#"interactive = ["keys_choose"]"#,
            ),
            |e| matches!(e, E::Interactive { .. }),
        ),
        (
            "network word",
            edit(r#"network = "pki""#, r#"network = "all""#),
            |e| matches!(e, E::Network { .. }),
        ),
        (
            "network outside capabilities.http",
            edit(
                r#"network = "pki""#,
                r#"network = ["https://evil.example/"]"#,
            ),
            |e| matches!(e, E::Network { why, .. } if why.contains("capabilities.http")),
        ),
        (
            "network empty list",
            edit(r#"network = "pki""#, "network = []"),
            |e| matches!(e, E::Network { .. }),
        ),
        (
            "key import without a key use",
            edit(r#""hash"]"#, r#""hash", "keys_sign_raw"]"#),
            |e| matches!(e, E::KeyUse { .. }),
        ),
        (
            "key use without its import",
            edit(r#""keys_sign_cms_ex", "#, ""),
            |e| matches!(e, E::KeyUse { .. }),
        ),
        (
            "request that is not JSON",
            edit(
                r#"request = '{"module":"example.sign","method":"signFile","args":["{file:base64}"]}'"#,
                r#"request = 'sign'"#,
            ),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "request for another module",
            edit(
                r#""module":"example.sign","method""#,
                r#""module":"example.other","method""#,
            ),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "extra request member",
            edit(r#""args":["#, r#""x":1,"args":["#),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "undeclared placeholder",
            edit("{file:base64}", "{nope:base64}"),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "document without base64",
            edit("{file:base64}", "{file}"),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "braces that are no placeholder",
            edit("{file:base64}", "x{file:base64}"),
            |e| matches!(e, E::Request { .. }),
        ),
        (
            "unused param",
            edit(
                "[operations.uses]",
                "[[operations.params]]\nname = \"extra\"\nkind = \"flag\"\n\n[operations.uses]",
            ),
            |e| matches!(e, E::Param { why, .. } if why.contains("not used")),
        ),
        (
            "duplicate param",
            edit(
                "[operations.uses]",
                "[[operations.params]]\nname = \"file\"\nkind = \"flag\"\n\n[operations.uses]",
            ),
            |e| matches!(e, E::Param { why, .. } if why.contains("twice")),
        ),
        (
            "bad param name",
            edit(r#"name = "file""#, r#"name = "File""#),
            |e| matches!(e, E::Param { .. }),
        ),
        (
            "stray param field",
            edit("max_bytes = 16777216", "max_bytes = 5\nmax_chars = 4"),
            |e| matches!(e, E::Param { .. }),
        ),
        (
            "document over the limit",
            edit("max_bytes = 16777216", "max_bytes = 999999999999"),
            |e| matches!(e, E::Param { .. }),
        ),
        (
            "choice without choices",
            edit(r#"kind = "document""#, r#"kind = "choice""#).replace("max_bytes = 16777216", ""),
            |e| matches!(e, E::Param { .. }),
        ),
        (
            "text as the content of cms_ex",
            edit(r#"kind = "document""#, r#"kind = "text""#)
                .replace("max_bytes = 16777216", "")
                .replace("{file:base64}", "{file}"),
            |e| matches!(e, E::KeyContent { .. }),
        ),
    ];
    for (what, text, check) in cases {
        let e = match parse(&text) {
            Err(PackageError::Operation(e)) => e,
            other => panic!("{what}: expected an operation error, got {other:?}"),
        };
        assert!(check(&e), "{what}: {e:?}");
    }
}

#[test]
fn operations_need_a_newer_min_core() {
    for old in ["0.1.0-alpha.6", "0.1.0-alpha.4", "0.0.9"] {
        let text = with(OP).replace(
            r#"min_core = "0.1.0-alpha.7""#,
            &format!("min_core = \"{old}\""),
        );
        let e = refused(&text);
        assert_eq!(
            e,
            OperationError::MinCore {
                needed: operations_min_core(),
                found: old.parse().unwrap()
            }
        );
    }
    // The bound itself and later ones are fine; a manifest without operations is not held
    // to it.
    parse(&with(OP)).unwrap();
    parse(&with(OP).replace("0.1.0-alpha.7\"", "0.2.0\"")).unwrap();
    parse(&HEAD.replace("0.1.0-alpha.7", "0.1.0-alpha.4")).unwrap();
}

#[test]
fn a_core_that_does_not_know_operations_refuses_the_table() {
    // The manifest of an older core is `deny_unknown_fields`: it refuses `operations`
    // outright, so a package that carries them cannot be installed there even if its
    // `min_core` were wrong. `min_core` above is the second gate, for cores that know the
    // key. This checks the first gate on the shape of that reader.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct OldManifest {
        id: String,
        version: String,
        min_core: String,
        modules: Vec<String>,
        name: toml::Value,
        capabilities: Option<toml::Value>,
    }
    let e = toml::from_str::<OldManifest>(&with(OP))
        .unwrap_err()
        .to_string();
    assert!(e.contains("unknown field `operations`"), "{e}");
    assert!(toml::from_str::<OldManifest>(HEAD).is_ok());
}

#[test]
fn too_many_operations_are_refused() {
    let mut text = HEAD.to_owned();
    for i in 0..33 {
        text.push_str(&OP.replace("sign-file", &format!("op-{i}")));
    }
    assert_eq!(refused(&text), OperationError::TooMany);
}

#[test]
fn xml_and_xades_profiles() {
    let xml = |kind: &str, import: &str, profile: &str, param: &str| {
        with(&format!(
            r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{{"module":"example.sign","method":"m","args":["{{doc:base64}}", "{{path}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "doc"
kind = "{param}"
[[operations.params]]
name = "path"
kind = "text"
[operations.uses]
imports = ["{import}"]
[[operations.uses.key]]
kind = "{kind}"
content = "param:doc"
[operations.uses.key.profile]
{profile}
"#
        ))
    };
    // A document or a text may be XML content; element comes from a text param.
    let ok = xml("xml", "keys_sign_xml", r#"element = "param:path""#, "text");
    // A text is not a base64 document: the placeholder `{doc:base64}` is refused for it.
    assert!(matches!(refused(&ok), OperationError::Request { .. }));
    let ok = xml(
        "xml_ex",
        "keys_sign_xml_ex",
        "element = \"/a/b\"\nparent = \"param:path\"\nplacement = \"parent\"\nsignature_method = \"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"",
        "document",
    );
    let manifest = parse(&ok).unwrap();
    let Profile::XmlEx(p) = manifest.operations()[0].uses().keys()[0].profile() else {
        panic!("xml_ex")
    };
    assert_eq!(p.element, Some(Source::Fixed("/a/b".to_owned())));
    assert_eq!(p.parent, Some(Source::Param("path".to_owned())));

    for (what, profile, wanted) in [
        (
            "parent without element",
            "parent = \"/a\"",
            "parent needs element",
        ),
        (
            "placement parent without parent",
            "placement = \"parent\"",
            "go together",
        ),
        (
            "parent without placement parent",
            "element = \"/a\"\nparent = \"/a\"",
            "go together",
        ),
        (
            "unknown signature method",
            "signature_method = \"urn:evil\"",
            "known method",
        ),
        (
            "unknown digest method",
            "digest_method = \"urn:evil\"",
            "known method",
        ),
        ("relative xpath", "element = \"a/b\"", "XPath"),
        ("param that is no text", "element = \"param:doc\"", "text"),
        ("undeclared param", "element = \"param:zz\"", "undeclared"),
        ("signature id", "signature_id = \"x\"", "signature_id"),
        ("transforms", "transforms = []", "transforms"),
        (
            "signing time object",
            "signing_time_object = {}",
            "signing_time_object",
        ),
    ] {
        let text = xml("xml_ex", "keys_sign_xml_ex", profile, "document");
        let e = match parse(&text) {
            Err(PackageError::Operation(OperationError::Profile { why, .. })) => why,
            Err(PackageError::Manifest(why)) => why,
            other => panic!("{what}: {other:?}"),
        };
        assert!(e.contains(wanted), "{what}: {e}");
    }

    let xades = |profile: &str| xml("xades", "keys_sign_xades", profile, "document");
    let manifest = parse(&xades("level = \"lt\"\ntsa = \"kalkan\"")).unwrap();
    assert!(matches!(
        manifest.operations()[0].uses().keys()[0].profile(),
        Profile::Xades(p) if p.level == oncl_pdk::abi::XadesLevel::Lt
    ));
    for profile in [
        "tsa = \"custom\"",
        "level = \"x\"",
        "chain = []",
        "signature_method = \"urn:evil\"",
    ] {
        assert!(parse(&xades(profile)).is_err(), "{profile}");
    }
}

#[test]
fn raw_and_plain_cms_profiles() {
    let make = |kind: &str, import: &str, profile: &str| {
        edit(r#"kind     = "cms_ex""#, &format!("kind = \"{kind}\""))
            .replace("keys_sign_cms_ex", import)
            .replace(
                "encapsulate  = false\ncosign       = \"never\"\ntimestamp    = \"basics\"\ncertificates = \"signer\"\noutput       = \"der\"",
                profile,
            )
    };
    parse(&make("raw", "keys_sign_raw", "")).unwrap();
    assert!(matches!(
        refused(&make("raw", "keys_sign_raw", "attached = true")),
        OperationError::Profile { .. }
    ));
    let cms = parse(&make(
        "cms",
        "keys_sign_cms",
        "attached = true\ntimestamp = \"basics\"",
    ))
    .unwrap();
    assert!(matches!(
        cms.operations()[0].uses().keys()[0].profile(),
        Profile::Cms(p) if p.attached && p.timestamp == Timestamp::Basics
    ));
    assert!(matches!(
        refused(&make("cms", "keys_sign_cms", "timestamp = \"kalkan\"")),
        OperationError::Profile { .. }
    ));
}

#[test]
fn keys_need_the_capability() {
    let text = with(OP).replace("keys = true\n", "");
    assert!(matches!(
        refused(&text),
        OperationError::UndeclaredImport { .. } | OperationError::KeyUse { .. }
    ));
}

// ---- canonical encoding ----------------------------------------------------------------

fn key_options(text: &str) -> Vec<u8> {
    let m = parse(text).unwrap();
    m.operations()[0].uses().keys()[0]
        .options_canonical(&|_| None)
        .unwrap()
}

#[test]
fn the_canonical_encoding_is_stable() {
    // A golden value: a change of the encoding is a change of every `options_sha256`
    // ever approved, so it must be deliberate (and versioned in the magic).
    let m = parse(&with(OP)).unwrap();
    let key = &m.operations()[0].uses().keys()[0];
    let bytes = key.options_canonical(&|_| None).unwrap();
    assert!(bytes.starts_with(b"ONCLOPT1\0\x03"));
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        "721f6636938156c8cfd5d965ce1107c6f84f7e3bf0b10b25ad314bc02333ef0d"
    );
    // magic, kind 3 (cms_ex), then field id and value: encapsulate 0, cosign 0, data 0,
    // time-stamp 1 (basics), signer 0, der 0, the three attributes 1, signing time now 0.
    assert_eq!(
        hex(&bytes),
        "4f4e434c4f50543100030100020003000401050006000701080109010a00"
    );
    assert_eq!(
        key.options_sha256(&|_| None).unwrap().to_vec(),
        Sha256::digest(&bytes).to_vec()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn unset_fields_encode_as_their_defaults() {
    let spelled = parse(&with(OP)).unwrap();
    let spelled = spelled.operations()[0].uses().keys()[0]
        .options_canonical(&|_| None)
        .unwrap();
    // The same profile with everything left to default but the time-stamp.
    let short = with(OP).replace(
        "encapsulate  = false\ncosign       = \"never\"\ntimestamp    = \"basics\"\ncertificates = \"signer\"\noutput       = \"der\"",
        "timestamp    = \"basics\"",
    );
    assert_eq!(key_options(&short), spelled);
    // And no timestamp at all differs.
    let none = with(OP).replace("timestamp    = \"basics\"\n", "");
    assert_ne!(key_options(&none), spelled);
}

#[test]
fn every_option_changes_the_encoding_and_none_collide() {
    let base = key_options(&with(OP));
    let mut seen = vec![base.clone()];
    for change in [
        ("encapsulate  = false", "encapsulate  = true"),
        ("timestamp    = \"basics\"", "timestamp    = \"kalkan\""),
        ("timestamp    = \"basics\"", "timestamp    = \"none\""),
        ("certificates = \"signer\"", "certificates = \"chain\""),
        ("output       = \"der\"", "output       = \"pem\""),
        ("output       = \"der\"", "output       = \"base64\""),
        (
            "output       = \"der\"",
            "output = \"der\"\ncontent_type = false",
        ),
        (
            "output       = \"der\"",
            "output = \"der\"\nmessage_digest = false",
        ),
        (
            "output       = \"der\"",
            "output = \"der\"\nsigning_certificate_v2 = false",
        ),
        (
            "output       = \"der\"",
            "output = \"der\"\nsigning_time = \"none\"",
        ),
        (
            "output       = \"der\"",
            "output = \"der\"\ncontent_form = \"digest\"",
        ),
    ] {
        let bytes = key_options(&edit(change.0, change.1));
        assert!(!seen.contains(&bytes), "{change:?} collides");
        seen.push(bytes);
    }
}

#[test]
fn strings_cannot_shift_between_fields() {
    // Length prefixes: ("ab", "c") and ("a", "bc") are different profiles.
    let make = |element: &str, parent: &str| {
        let text = with(&format!(
            r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{{"module":"example.sign","method":"m","args":["{{doc:base64}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "doc"
kind = "document"
[operations.uses]
imports = ["keys_sign_xml_ex"]
[[operations.uses.key]]
kind = "xml_ex"
content = "param:doc"
[operations.uses.key.profile]
element = "{element}"
parent = "{parent}"
placement = "parent"
"#
        ));
        key_options(&text)
    };
    assert_ne!(make("/ab", "/c"), make("/a", "/bc"));
    assert_ne!(make("/a", "/b"), make("/b", "/a"));
}

#[test]
fn a_param_source_encodes_as_the_text_it_is_given() {
    let text = with(
        r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{"module":"example.sign","method":"m","args":["{doc:base64}","{path}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "doc"
kind = "document"
[[operations.params]]
name = "path"
kind = "text"
[operations.uses]
imports = ["keys_sign_xml"]
[[operations.uses.key]]
kind = "xml"
content = "param:doc"
[operations.uses.key.profile]
element = "param:path"
"#,
    );
    let m = parse(&text).unwrap();
    let key = &m.operations()[0].uses().keys()[0];
    // Unresolved: no hash.
    assert_eq!(key.options_canonical(&|_| None), None);
    let resolved =
        |v: &'static str| key.options_canonical(&move |n| (n == "path").then(|| v.to_owned()));
    let fixed = text.replace("element = \"param:path\"", "element = \"/a/b\"");
    let fixed = parse(&fixed).unwrap();
    assert_eq!(
        resolved("/a/b"),
        fixed.operations()[0].uses().keys()[0].options_canonical(&|_| None),
        "a resolved param is a fixed value"
    );
    assert_ne!(resolved("/a/b"), resolved("/a/c"));
}

#[test]
fn the_declaration_canonical_ignores_the_label_only() {
    let a = parse(&with(OP)).unwrap().operations()[0].canonical();
    let relabelled = parse(&edit(r#"en = "Sign a file""#, r#"en = "Do it""#)).unwrap();
    assert_eq!(relabelled.operations()[0].canonical(), a);
    let other = parse(&edit(r#"network = "pki""#, r#"network = "none""#)).unwrap();
    assert_ne!(other.operations()[0].canonical(), a);
    // The order of imports is not significant; their set is.
    let reordered = parse(&edit(
        r#"imports = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"]"#,
        r#"imports = ["hash", "keys_sign_cms_ex", "keys_describe", "keys_select"]"#,
    ))
    .unwrap();
    assert_eq!(reordered.operations()[0].canonical(), a);
    assert_eq!(
        reordered.operations()[0].sha256().to_vec(),
        Sha256::digest(&a).to_vec()
    );
}

// ---- updates ---------------------------------------------------------------------------

fn added(new: &str, old: &str) -> oncl_plugin::Added {
    parse(new).unwrap().added_over(&parse(old).unwrap())
}

#[test]
fn an_update_adding_a_key_operation_asks() {
    // The operation appears.
    let a = added(&with(OP), HEAD);
    assert!(!a.is_empty());
    assert_eq!(a.operations[0].name, "sign-file");
    // Existing capability semantics are untouched: equal capabilities add none.
    assert!(a.capabilities.is_empty());
    // The same manifest adds nothing.
    assert!(added(&with(OP), &with(OP)).is_empty());
    // A new capability is still an addition.
    let more = with(OP).replace("keys = true", "keys = true\nsettings = true");
    assert!(!added(&more, &with(OP)).capabilities.is_empty());
}

#[test]
fn an_update_changing_an_operation_asks_only_when_it_widens() {
    let old = with(OP);
    for (what, change) in [
        (
            "profile",
            ("timestamp    = \"basics\"", "timestamp    = \"kalkan\""),
        ),
        (
            "output",
            ("output       = \"der\"", "output       = \"pem\""),
        ),
        (
            "network",
            (
                r#"network = "pki""#,
                r#"network = ["https://api.example.kz/v1/"]"#,
            ),
        ),
        ("imports", (r#""hash"]"#, r#""hash", "tsp_request"]"#)),
        ("server", ("server  = false", "server  = true")),
        (
            "request",
            (r#""method":"signFile""#, r#""method":"signOther""#),
        ),
        ("content", ("max_bytes = 16777216", "max_bytes = 1048576")),
    ] {
        let a = added(&edit(change.0, change.1), &old);
        assert!(!a.is_empty(), "{what} must ask: {a:?}");
    }
    // Not a widening: the label, and removals.
    assert!(added(&edit(r#"en = "Sign a file""#, r#"en = "Other""#), &old).is_empty());
    let narrower = edit(r#"network = "pki""#, r#"network = "none""#);
    assert!(
        added(&narrower, &old).is_empty(),
        "{:?}",
        added(&narrower, &old)
    );
    let fewer = edit(r#"interactive = ["keys_select"]"#, "interactive = []");
    assert!(added(&fewer, &old).is_empty());
}

#[test]
fn a_profile_change_in_one_of_two_operations_names_that_one() {
    let two = |second: &str| {
        let renamed = OP
            .replace("sign-file", "other-op")
            .replace(second, &second.replace("basics", "kalkan"));
        with(&format!("{OP}{renamed}"))
    };
    let old = two("zzz-not-present");
    let new = two("\"basics\"");
    let a = added(&new, &old);
    assert_eq!(a.operations.len(), 1);
    assert_eq!(a.operations[0].name, "other-op");
}

#[test]
fn a_non_key_operation_with_nothing_new_does_not_ask() {
    let plain = r#"
[[operations]]
name = "info"
module = "example.sign"
manual = true
request = '{"module":"example.sign","method":"info","args":[]}'
label = { ru = "а", kk = "ә", en = "a" }
[operations.uses]
imports = ["hash", "now"]
"#;
    assert!(added(&with(plain), HEAD).is_empty());
}

// ---- the package's imports -------------------------------------------------------------

#[test]
fn an_operation_may_not_list_an_import_the_module_lacks() {
    use common::{answering, wasm};
    let text = with(OP);
    let manifest = parse(&text).unwrap();
    // `answering` imports nothing: the operation's imports are not the module's.
    let wat = answering(r#"{"status":true}"#);
    match Engine::new().compile(&manifest, &wasm(&wat)) {
        Err(LoadError::OperationImport { operation, name }) => {
            assert_eq!(operation, "sign-file");
            assert_eq!(name, "keys_select");
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    // A module that imports all four is accepted.
    let host = "(param i32 i32) (result i64)";
    let mut wat = wat;
    for name in ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"] {
        wat = wat.replacen(
            "(module",
            &format!("(module (import \"oncl\" \"{name}\" (func {host}))"),
            1,
        );
    }
    Engine::new().compile(&manifest, &wasm(&wat)).unwrap();
}
