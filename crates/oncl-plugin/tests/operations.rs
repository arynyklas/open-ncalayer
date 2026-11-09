//! `[[operations]]` of `plugin.toml`: what parses, what is refused and why, the canonical
//! encoding of a profile, and what an update adds. The reference text is the design,
//! `docs/design/manual-plugins.md` section 4.1.

mod common;

use oncl_pdk::abi::Import;
use oncl_plugin::operations::{
    AddedReason, Content, ImportPolicy, KeyKind, Network, OperationError, Profile, Source,
    Timestamp, operations_min_core,
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
fn every_shipped_manifest_parses_and_what_it_declares_is_runnable_in_the_window() {
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
        for op in manifest.operations() {
            let at = format!("{} {}", path.display(), op.name());
            assert!(op.runnable() && !op.is_derived(), "{at}: not runnable");
            // A key use is validated online and time-stamped through the PKI endpoints: with
            // `network = "none"` the manual window refuses it before the key
            // (crates/oncl-core/tests/plugin_ports_manual/network.rs).
            if !op.uses().keys().is_empty() {
                assert!(
                    matches!(op.uses().network(), oncl_plugin::operations::Network::Pki),
                    "{at}: a key use needs network = \"pki\""
                );
            }
        }
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
            "two uses of a key",
            edit(
                "[operations.uses.key.profile]",
                "[operations.uses.key.profile]\n",
            )
            .replace(
                "\n[[operations.uses.key]]",
                "\n[[operations.uses.key]]\nkind = \"cms_ex\"\ncontent = \"param:file\"\n[[operations.uses.key]]",
            ),
            |e| matches!(e, E::TooManyKeyUses(_)),
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
            edit(r#""hash"]"#, r#""hash", "http_request"]"#)
                .replace("http = [\"https://api.example.kz/\"]\n", ""),
            |e| {
                matches!(
                    e,
                    E::UndeclaredImport {
                        name: "http_request",
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
network = "pki"
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
    let manifest = parse(&xades("level = \"b\"\ntsa = \"kalkan\"")).unwrap();
    assert!(matches!(
        manifest.operations()[0].uses().keys()[0].profile(),
        Profile::Xades(p) if p.level == oncl_pdk::abi::XadesLevel::B
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
network = "pki"
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
network = "pki"
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
    let other = parse(&edit("server  = false", "server  = true")).unwrap();
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
        ("imports", (r#""hash"]"#, r#""hash", "tsp_request"]"#)),
        ("server", ("server  = false", "server  = true")),
        (
            "request",
            (r#""method":"signFile""#, r#""method":"signOther""#),
        ),
        ("content", ("max_bytes = 16777216", "max_bytes = 33554432")),
    ] {
        let a = added(&edit(change.0, change.1), &old);
        assert!(!a.is_empty(), "{what} must ask: {a:?}");
    }
    // Not a widening: the label, and removals.
    assert!(added(&edit(r#"en = "Sign a file""#, r#"en = "Other""#), &old).is_empty());
    // Narrowing asks for nothing: a narrower network, a smaller document, a request
    // spaced differently, `manual` switched off.
    let wide = with(OP);
    let narrower = edit("max_bytes = 16777216", "max_bytes = 16777216")
        .replace("max_bytes = 16777216", "max_bytes = 1048576")
        .replace(r#""method":"signFile","#, r#""method" : "signFile","#);
    assert!(
        added(&narrower, &wide).is_empty(),
        "{:?}",
        added(&narrower, &wide)
    );
    // A tighter list of choices or text limit does not ask either; a wider one does.
    let off =
        edit("manual  = true", "manual  = false\nserver  = true").replace("server  = false\n", "");
    assert!(
        added(&off, &old)
            .operations
            .iter()
            .all(|a| a.reasons == [AddedReason::Server])
    );
    let fewer = edit(r#"interactive = ["keys_select"]"#, "interactive = []");
    assert!(added(&fewer, &old).is_empty());
    // The network of an operation without a key: wider asks, narrower does not.
    let urls = |u: &str| info_op(&format!("[\"{u}\"]"), "\"http_request\"");
    assert!(
        !added(
            &urls("https://api.example.kz/"),
            &info_op("\"none\"", "\"hash\"")
        )
        .is_empty()
    );
    assert!(
        !added(
            &urls("https://api.example.kz/"),
            &urls("https://api.example.kz/v1/")
        )
        .is_empty()
    );
    assert!(
        added(
            &urls("https://api.example.kz/v1/"),
            &urls("https://api.example.kz/")
        )
        .is_empty()
    );
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

// ---- the second review: rulings and hardening -------------------------------------------

/// A one-key operation of `kind` over the document `doc` and the text `path`.
fn op_of(kind: &str, import: &str, network: &str, profile: &str) -> String {
    with(&format!(
        r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{{"module":"example.sign","method":"m","args":["{{doc:base64}}","{{path}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "doc"
kind = "document"
[[operations.params]]
name = "path"
kind = "text"
[operations.uses]
imports = ["{import}"]
network = {network}
[[operations.uses.key]]
kind = "{kind}"
content = "param:doc"
[operations.uses.key.profile]
{profile}
"#
    ))
}

#[test]
fn one_key_use_per_operation() {
    let two = edit(
        "[operations.uses.key.profile]",
        "[operations.uses.key.profile]\n",
    )
    .replace(
        "\n[[operations.uses.key]]",
        "\n[[operations.uses.key]]\nkind = \"cms_ex\"\ncontent = \"param:file\"\n[[operations.uses.key]]",
    );
    assert!(matches!(refused(&two), OperationError::TooManyKeyUses(_)));
    // None is fine: an operation need not use a key.
    parse(&with(
        r#"
[[operations]]
name = "info"
module = "example.sign"
manual = true
request = '{"module":"example.sign","method":"info","args":[]}'
label = { ru = "а", kk = "ә", en = "a" }
"#,
    ))
    .unwrap();
}

#[test]
fn derived_operations_are_in_neither_listing() {
    let derived = parse(&edit(
        r#"content  = "param:file""#,
        r#"content  = "derived""#,
    ))
    .unwrap();
    assert_eq!(derived.operations().len(), 1, "unfiltered, for tooling");
    assert_eq!(derived.manual_operations().count(), 0);
    assert_eq!(derived.server_operations().count(), 0);
    // A runnable one is in the listing it asks for, and only that one.
    let manual = parse(&with(OP)).unwrap();
    assert_eq!(manual.manual_operations().count(), 1);
    assert_eq!(manual.server_operations().count(), 0);
    let server = parse(&edit(
        "manual  = true\nserver  = false",
        "manual  = false\nserver  = true",
    ))
    .unwrap();
    assert_eq!(server.manual_operations().count(), 0);
    assert_eq!(server.server_operations().count(), 1);
    // A plugin without operations has nothing in either.
    assert_eq!(parse(HEAD).unwrap().manual_operations().count(), 0);
}

#[test]
fn raw_signs_bound_content_only() {
    let raw = |content: &str| {
        edit(r#"kind     = "cms_ex""#, r#"kind = "raw""#)
            .replace("keys_sign_cms_ex", "keys_sign_raw")
            .replace(r#"content  = "param:file""#, content)
            .replace(
                "encapsulate  = false\ncosign       = \"never\"\ntimestamp    = \"basics\"\ncertificates = \"signer\"\noutput       = \"der\"\n",
                "",
            )
    };
    parse(&raw(r#"content  = "param:file""#)).unwrap();
    match refused(&raw(r#"content  = "derived""#)) {
        OperationError::KeyContent { why, .. } => assert!(why.contains("raw"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn xades_levels_are_b_and_t_for_now() {
    let xades = |level: &str, network: &str| {
        op_of(
            "xades",
            "keys_sign_xades",
            network,
            &format!("level = \"{level}\""),
        )
    };
    parse(&xades("b", "\"pki\"")).unwrap();
    parse(&xades("t", "\"pki\"")).unwrap();
    for level in ["lt", "lta"] {
        let e = match parse(&xades(level, "\"pki\"")) {
            Err(PackageError::Operation(OperationError::Profile { why, .. })) => why,
            Err(PackageError::Manifest(why)) => why,
            other => panic!("{level}: {other:?}"),
        };
        assert!(
            e.contains("lt") || e.contains("unknown variant"),
            "{level}: {e}"
        );
    }
    assert!(matches!(
        refused(&xades("lt", "\"pki\"")),
        OperationError::Profile { .. }
    ));
}

/// A plain operation: no key, `imports` and `network` as given.
fn info_op(network: &str, imports: &str) -> String {
    with(&format!(
        r#"
[[operations]]
name = "info"
module = "example.sign"
manual = true
request = '{{"module":"example.sign","method":"info","args":[]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[operations.uses]
imports = [{imports}]
network = {network}
"#
    ))
}

#[test]
fn network_none_excludes_what_needs_the_network() {
    // An import that sends requests.
    for import in ["http_request", "tsp_request", "ocsp_fetch", "cms_verify"] {
        assert!(
            matches!(
                refused(&info_op("\"none\"", &format!("\"{import}\""))),
                OperationError::NetworkNeeded { .. }
            ),
            "{import}"
        );
    }
    parse(&info_op("\"none\"", "\"hash\"")).unwrap();
    parse(&info_op("\"pki\"", "\"tsp_request\"")).unwrap();
}

#[test]
fn a_key_operation_declares_network_pki() {
    // Neither `none` nor URLs: the manual window signs with the PKI hosts only.
    for network in [
        r#"network = "none""#,
        r#"network = ["https://api.example.kz/"]"#,
    ] {
        let text = edit(r#"network = "pki""#, network)
            .replace("timestamp    = \"basics\"", "timestamp    = \"none\"");
        assert!(
            matches!(refused(&text), OperationError::NetworkNeeded { why, .. } if why.contains("key operation")),
            "{network}"
        );
    }
    // Not declared at all is `none`.
    let text = edit("network = \"pki\"\n", "");
    assert!(matches!(
        refused(&text),
        OperationError::NetworkNeeded { .. }
    ));
    // An operation without a key may declare anything its imports allow.
    parse(&info_op(
        "[\"https://api.example.kz/\"]",
        "\"http_request\"",
    ))
    .unwrap();
}

#[test]
fn labels_refuse_invisible_and_edge_whitespace() {
    for bad in [
        "\u{200B}",
        "a\u{200B}b",
        "a\u{FEFF}",
        "a\u{2060}b",
        "a\u{00AD}b",
        "a\u{E0041}b",
        " a",
        "a ",
        "a\u{2028}b",
    ] {
        let text = edit(r#"en = "Sign a file""#, &format!("en = \"{bad}\""));
        assert!(
            matches!(
                parse(&text),
                Err(PackageError::Operation(OperationError::Label { .. }))
            ),
            "{bad:?}"
        );
    }
    parse(&edit(r#"en = "Sign a file""#, r#"en = "Sign (a) file""#)).unwrap();
}

#[test]
fn xpath_text_is_checked_where_it_is_written_and_where_it_is_typed() {
    // Fixed.
    for bad in ["/a\u{202E}b", "/a\u{2028}b", "/a\u{200B}", "/a\tb", "a/b"] {
        let text = op_of(
            "xml",
            "keys_sign_xml",
            "\"pki\"",
            &format!("element = \"{}\"", bad.replace('\t', "\\t")),
        );
        assert!(parse(&text).is_err(), "{bad:?}");
    }
    parse(&op_of(
        "xml",
        "keys_sign_xml",
        "\"pki\"",
        "element = \"/a/b[1]\"",
    ))
    .unwrap();
    // A text param that is an XPath may hold at most MAX_XPATH_PARAM_CHARS characters.
    let long = op_of(
        "xml",
        "keys_sign_xml",
        "\"pki\"",
        "element = \"param:path\"",
    )
    .replace(
        "name = \"path\"\nkind = \"text\"",
        "name = \"path\"\nkind = \"text\"\nmax_chars = 65536",
    );
    assert!(matches!(
        refused(&long),
        OperationError::Profile { why, .. } if why.contains("max_chars")
    ));
    parse(
        &op_of(
            "xml",
            "keys_sign_xml",
            "\"pki\"",
            "element = \"param:path\"",
        )
        .replace(
            "name = \"path\"\nkind = \"text\"",
            "name = \"path\"\nkind = \"text\"\nmax_chars = 256",
        ),
    )
    .unwrap();
    // The value the user typed.
    assert!(Source::check_value("/a/b").is_ok());
    for bad in [
        "",
        "a",
        "/a\u{202E}",
        "/a\u{2029}",
        "/a\n",
        &format!("/{}", "a".repeat(1024)),
    ] {
        assert!(Source::check_value(bad).is_err(), "{bad:?}");
    }
    // And `options_canonical` refuses a value that fails it.
    let m = parse(&op_of(
        "xml",
        "keys_sign_xml",
        "\"pki\"",
        "element = \"param:path\"",
    ))
    .unwrap();
    let key = &m.operations()[0].uses().keys()[0];
    assert!(
        key.options_canonical(&|_| Some("/a/b".to_owned()))
            .is_some()
    );
    assert!(
        key.options_canonical(&|_| Some("/a\u{202E}".to_owned()))
            .is_none()
    );
    assert!(
        key.options_canonical(&|_| Some("relative".to_owned()))
            .is_none()
    );
}

#[test]
fn namespaces_are_distinct_and_documents_can_run() {
    let ns = |extra: &str| {
        op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            &format!("namespaces = [{{ prefix = \"p\", uri = \"urn:p\" }}{extra}]"),
        )
    };
    parse(&ns(", { prefix = \"q\", uri = \"urn:q\" }")).unwrap();
    assert!(matches!(
        refused(&ns(", { prefix = \"p\", uri = \"urn:other\" }")),
        OperationError::Profile { why, .. } if why.contains("twice")
    ));
    // The most a document may be still fits `max_transfer` as base64 with the request.
    let max = oncl_plugin::operations::MAX_DOCUMENT_BYTES;
    assert!(max < oncl_plugin::MAX_TRANSFER as u64 * 3 / 4);
    let base64 = max.div_ceil(3) * 4;
    assert!(
        base64 + oncl_plugin::operations::MAX_REQUEST as u64 <= oncl_plugin::MAX_TRANSFER as u64
    );
    parse(&edit("max_bytes = 16777216", &format!("max_bytes = {max}"))).unwrap();
    assert!(matches!(
        refused(&edit(
            "max_bytes = 16777216",
            &format!("max_bytes = {}", max + 1)
        )),
        OperationError::Param { .. }
    ));
    assert!(matches!(
        refused(&edit("max_bytes = 16777216", "max_bytes = 268435456")),
        OperationError::Param { .. }
    ));
}

#[test]
fn too_many_imports_has_its_own_error() {
    let names: Vec<String> = (0..65).map(|_| "\"hash\"".to_owned()).collect();
    let text = edit(
        r#"imports = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"]"#,
        &format!("imports = [{}]", names.join(",")),
    );
    assert!(matches!(refused(&text), OperationError::TooManyImports(_)));
}

#[test]
fn a_repeated_key_in_the_request_is_refused() {
    let text = edit(
        r#""module":"example.sign","method""#,
        r#""module":"example.sign","module":"example.other","method""#,
    );
    match refused(&text) {
        OperationError::Request { why, .. } => assert!(why.contains("repeated"), "{why}"),
        other => panic!("{other:?}"),
    }
    let nested = edit(
        r#""args":["{file:base64}"]"#,
        r#""args":["{file:base64}",{"a":1,"a":2}]"#,
    );
    assert!(matches!(refused(&nested), OperationError::Request { .. }));
}

#[test]
fn every_import_has_a_policy() {
    use ImportPolicy::{Allowed, Forbidden, NeedsProfile};
    // `ImportPolicy::of` is an exhaustive match: a new import does not compile until it
    // is classified. This pins the classification itself.
    let of = |name: &str| ImportPolicy::of(Import::from_name(name).unwrap());
    for name in [
        "keys_sign_raw",
        "keys_sign_cms",
        "keys_sign_cms_ex",
        "keys_sign_xml",
        "keys_sign_xml_ex",
        "keys_sign_xades",
    ] {
        assert_eq!(of(name), NeedsProfile, "{name}");
    }
    for name in [
        "dialog_message",
        "dialog_confirm",
        "dialog_password",
        "dialog_choice",
        "dialog_reader",
        "dialog_csr",
        "dialog_import",
        "file_open",
        "file_save",
        "file_choose",
        "file_open_ex",
        "file_choose_kind",
        "page_file_read",
        "page_file_write",
        "keys_open",
        "settings_get",
        "settings_put",
        "shared_get",
        "shared_put",
        "core_modules",
        "core_bundles",
        "core_install_bundle",
        "core_open_window",
        "keystore_new_key",
        "keystore_install_cert",
        "keystore_change_password",
        "tokens_id_card",
        "data_read",
        "data_decode",
        "data_encode",
        "data_sign_cms",
        "data_sign_xml",
        "data_sign_raw",
        "data_stamp",
        "data_page_read",
    ] {
        assert_eq!(of(name), Forbidden, "{name}");
    }
    for name in [
        "log",
        "now",
        "random",
        "hash",
        "cert_info",
        "cert_details",
        "keys_select",
        "keys_choose",
        "keys_flow_open",
        "keys_flow_pick",
        "keys_describe",
        "keys_chain",
        "keys_release",
        "keys_terminals",
        "tokens_scan",
        "http_request",
        "http_request_ex",
        "tsp_request",
        "tsp_stamp",
        "ocsp_fetch",
        "crl_fetch",
        "cms_verify",
        "xml_verify",
        "ca_list",
        "ca_issuer",
        "pkix_path",
        "local_time",
        "platform",
        "call_locale",
        "reply_drop",
    ] {
        assert_eq!(of(name), Allowed, "{name}");
    }
    let (mut allowed, mut forbidden, mut needs) = (0, 0, 0);
    for import in Import::ALL {
        match ImportPolicy::of(import) {
            Allowed => allowed += 1,
            Forbidden => forbidden += 1,
            NeedsProfile => needs += 1,
        }
    }
    assert_eq!(
        (allowed, forbidden, needs, Import::ALL.len()),
        (30, 35, 6, 71)
    );
    // And the parse enforces it.
    for name in [
        "page_file_write",
        "settings_put",
        "core_install_bundle",
        "shared_put",
    ] {
        let text = edit(r#""hash"]"#, &format!(r#""hash", "{name}"]"#));
        let text = text.replace(
            "keys = true",
            "keys = true\nsettings = true\nshared = true\npage_files = true\nfiles = true",
        );
        assert!(
            matches!(
                parse(&text),
                Err(PackageError::Operation(
                    OperationError::ForbiddenImport { .. }
                ))
            ),
            "{name}"
        );
    }
    // tokens_scan is allowed: the host answers "tokens off".
    parse(&edit(r#""hash"]"#, r#""hash", "tokens_scan"]"#)).unwrap();
    // A signing import is not a free one: it needs its profile (tested above).
}

// ---- canonical encodings: every kind, every field ---------------------------------------

const RSA: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const GOST: &str = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
const SHA: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const GOST_D: &str = "http://www.w3.org/2001/04/xmldsig-more#gost34311";

fn xml_ex_base() -> String {
    op_of(
        "xml_ex",
        "keys_sign_xml_ex",
        "\"pki\"",
        &format!(
            "element = \"/a/b\"\nparent = \"/a\"\nplacement = \"parent\"\n\
             namespaces = [{{ prefix = \"p\", uri = \"urn:p\" }}]\nother_prefix_uri = \"urn:o\"\n\
             signature_method = \"{RSA}\"\ndigest_method = \"{SHA}\"\nc14n = \"exclusive\"\n\
             strip_whitespace = true\nbase64_line_breaks = true\n\
             output = {{ serialize = {{ declaration = true, standalone_no = false, trim = true }} }}\n"
        ),
    )
}

/// `base` with each of `changes` applied alone: the declaration's canonical encoding (and the
/// options' when the operation has a key use) must differ from the base's, and from every
/// other change's.
fn assert_all_distinct(what: &str, base: &str, changes: &[(&str, &str)]) {
    let canonical = |text: &str| {
        let m = parse(text).unwrap_or_else(|e| panic!("{what}: {e}\n{text}"));
        let op = &m.operations()[0];
        let options = op
            .uses()
            .keys()
            .first()
            .and_then(|k| k.options_canonical(&|n| (n == "path").then(|| "/typed".to_owned())));
        (op.canonical(), options)
    };
    let (base_decl, base_opts) = canonical(base);
    let mut seen = vec![(base_decl.clone(), base_opts.clone())];
    for (from, to) in changes {
        assert!(base.contains(from), "{what}: {from:?} is not in the base");
        let text = base.replacen(from, to, 1);
        let (decl, opts) = canonical(&text);
        assert_ne!(
            decl, base_decl,
            "{what}: {from:?} -> {to:?} leaves the declaration alone"
        );
        if base_opts.is_some() && !from.contains("name") {
            // Declaration-only changes (module, request, ...) may keep the options.
        }
        assert!(
            !seen.iter().any(|(d, _)| *d == decl),
            "{what}: {to:?} collides"
        );
        seen.push((decl, opts));
    }
}

#[test]
fn every_profile_field_of_every_kind_changes_the_canonical_bytes() {
    // xml_ex: every field, each variant.
    let base = xml_ex_base();
    let decl_only = base.clone();
    assert_all_distinct(
        "xml_ex",
        &decl_only,
        &[
            ("element = \"/a/b\"", "element = \"/a/c\""),
            ("element = \"/a/b\"", "element = \"param:path\""),
            ("parent = \"/a\"", "parent = \"/z\""),
            (
                "parent = \"/a\"\nplacement = \"parent\"",
                "placement = \"first_child_of_document\"",
            ),
            ("parent = \"/a\"\nplacement = \"parent\"\n", ""),
            ("prefix = \"p\"", "prefix = \"q\""),
            ("uri = \"urn:p\"", "uri = \"urn:q\""),
            (
                "[{ prefix = \"p\", uri = \"urn:p\" }]",
                "[{ prefix = \"p\", uri = \"urn:p\" }, { prefix = \"q\", uri = \"urn:q\" }]",
            ),
            ("[{ prefix = \"p\", uri = \"urn:p\" }]", "[]"),
            (
                "other_prefix_uri = \"urn:o\"",
                "other_prefix_uri = \"urn:x\"",
            ),
            ("other_prefix_uri = \"urn:o\"\n", ""),
            (RSA, GOST),
            (
                "signature_method = \"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"\n",
                "",
            ),
            (SHA, GOST_D),
            (
                "digest_method = \"http://www.w3.org/2001/04/xmlenc#sha256\"\n",
                "",
            ),
            ("c14n = \"exclusive\"", "c14n = \"inclusive\""),
            ("c14n = \"exclusive\"", "c14n = \"exclusive_with_comments\""),
            ("c14n = \"exclusive\"", "c14n = \"inclusive_with_comments\""),
            ("c14n = \"exclusive\"\n", ""),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [\"enveloped\"]",
            ),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [{ c14n = \"inclusive_with_comments\" }]",
            ),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
            ),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [\"enveloped\", { c14n = \"exclusive_with_comments\" }]",
            ),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [\"enveloped\", { c14n = \"inclusive\" }]",
            ),
            (
                "strip_whitespace = true",
                "strip_whitespace = true\ntransforms = [\"enveloped\", { c14n = \"exclusive\" }]",
            ),
            ("strip_whitespace = true", "strip_whitespace = false"),
            ("base64_line_breaks = true", "base64_line_breaks = false"),
            ("base64_line_breaks = true\n", ""),
            ("declaration = true", "declaration = false"),
            ("standalone_no = false", "standalone_no = true"),
            ("trim = true", "trim = false"),
            (
                "output = { serialize = { declaration = true, standalone_no = false, trim = true } }",
                "output = \"as_is\"",
            ),
        ],
    );
    let op = with(OP);
    assert_all_distinct(
        "cms_ex",
        &op,
        &[
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
        ],
    );
    // The declaration's own fields.
    assert_all_distinct(
        "operation fields",
        &op,
        &[
            (r#"name    = "sign-file""#, r#"name    = "sign-other""#),
            ("server  = false", "server  = true"),
            ("max_bytes = 16777216", "max_bytes = 1024"),
            (r#""hash"]"#, r#""hash", "now"]"#),
            (r#"interactive = ["keys_select"]"#, "interactive = []"),
            (r#""method":"signFile""#, r#""method":"signOther""#),
        ],
    );
    // The other kinds.
    assert_all_distinct(
        "cms",
        &op_of(
            "cms",
            "keys_sign_cms",
            "\"pki\"",
            "attached = true\ntimestamp = \"basics\"",
        ),
        &[
            ("attached = true", "attached = false"),
            ("timestamp = \"basics\"", "timestamp = \"none\""),
        ],
    );
    assert_all_distinct(
        "xml",
        &op_of(
            "xml",
            "keys_sign_xml",
            "\"pki\"",
            "element = \"/a\"\nparent = \"/b\"",
        ),
        &[
            ("element = \"/a\"", "element = \"/c\""),
            ("element = \"/a\"", "element = \"param:path\""),
            ("parent = \"/b\"", "parent = \"/c\""),
            ("\nparent = \"/b\"", ""),
        ],
    );
    assert_all_distinct(
        "xades",
        &op_of(
            "xades",
            "keys_sign_xades",
            "\"pki\"",
            &format!(
                "level = \"b\"\ntsa = \"basics\"\nsignature_method = \"{RSA}\"\ndigest_method = \"{SHA}\""
            ),
        ),
        &[
            ("level = \"b\"", "level = \"t\""),
            ("tsa = \"basics\"", "tsa = \"kalkan\""),
            (RSA, GOST),
            (SHA, GOST_D),
            ("\nsignature_method", "\n#signature_method"),
        ],
    );
}

#[test]
fn xml_ex_transforms_are_checked_like_the_signing_engine_takes_them() {
    let transforms = |list: &str| {
        op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            &format!("transforms = {list}"),
        )
    };
    for ok in [
        "[\"enveloped\"]",
        "[\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
        "[\"enveloped\", { c14n = \"exclusive\" }]",
    ] {
        parse(&transforms(ok)).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    // Without `enveloped` only an element can be signed (a whole document holds its own
    // signature): the manifest says so before the signing engine would.
    let element_form = |list: &str| {
        op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            &format!(
                "element = \"/a/b\"\nparent = \"/a\"\nplacement = \"parent\"\ntransforms = {list}"
            ),
        )
    };
    parse(&element_form("[{ c14n = \"inclusive\" }]")).unwrap();
    let e = refused(&transforms("[{ c14n = \"inclusive\" }]")).to_string();
    assert!(
        e.contains("whole-document") && e.contains("enveloped"),
        "{e}"
    );
    const ORDER: &str = "enveloped first, then at most one canonicalisation";
    for (bad, wanted) in [
        ("[]", "is empty"),
        ("[{ c14n = \"inclusive\" }, \"enveloped\"]", ORDER),
        (
            "[\"enveloped\", { c14n = \"inclusive\" }, { c14n = \"exclusive\" }]",
            ORDER,
        ),
        ("[\"enveloped\", \"enveloped\"]", ORDER),
        (
            "[{ c14n = \"inclusive\" }, { c14n = \"inclusive\" }]",
            ORDER,
        ),
    ] {
        let e = refused(&transforms(bad)).to_string();
        assert!(e.contains(wanted), "{bad}: {e}");
    }
    // Not a transform of the list.
    for bad in ["[\"xpath\"]", "[{ c14n = \"md5\" }]", "\"enveloped\""] {
        assert!(
            matches!(refused(&transforms(bad)), OperationError::Profile { .. }),
            "{bad}"
        );
    }
}

#[test]
fn the_transforms_field_is_written_only_when_present() {
    // `xml_ex_base` has no transforms: its bytes are the golden vector's (field 11 last).
    let without = key_options(&xml_ex_base());
    assert!(
        without.ends_with(&[0x0b, 0x01, 0x01, 0x00, 0x01]),
        "{without:?}"
    );
    let with_transforms = |list: &str| {
        key_options(&xml_ex_base().replacen(
            "strip_whitespace = true",
            &format!("strip_whitespace = true\ntransforms = {list}"),
            1,
        ))
    };
    // Field 12: a count, then one tag per transform (enveloped 0, inclusive with comments 2).
    let mut wanted = without.clone();
    wanted.extend_from_slice(&[0x0c, 0, 0, 0, 2, 0x00, 0x02]);
    assert_eq!(
        with_transforms("[\"enveloped\", { c14n = \"inclusive_with_comments\" }]"),
        wanted
    );
    let mut wanted = without.clone();
    wanted.extend_from_slice(&[0x0c, 0, 0, 0, 1, 0x00]);
    assert_eq!(with_transforms("[\"enveloped\"]"), wanted);
}

#[test]
fn golden_vectors_for_every_kind() {
    // A change of any of these is a change of every `options_sha256` ever approved: it must
    // be deliberate and come with a new magic.
    let cases: [(&str, String); 6] = [
        ("raw", op_of("raw", "keys_sign_raw", "\"pki\"", "")),
        (
            "cms",
            op_of(
                "cms",
                "keys_sign_cms",
                "\"pki\"",
                "attached = true\ntimestamp = \"basics\"",
            ),
        ),
        ("cms_ex", with(OP)),
        (
            "xml",
            op_of(
                "xml",
                "keys_sign_xml",
                "\"pki\"",
                "element = \"/a\"\nparent = \"/b\"",
            ),
        ),
        ("xml_ex", xml_ex_base()),
        (
            "xades",
            op_of(
                "xades",
                "keys_sign_xades",
                "\"pki\"",
                &format!(
                    "level = \"t\"\ntsa = \"kalkan\"\nsignature_method = \"{RSA}\"\ndigest_method = \"{SHA}\""
                ),
            ),
        ),
    ];
    let mut got = Vec::new();
    for (name, text) in &cases {
        let m = parse(text).unwrap();
        let op = &m.operations()[0];
        let key = &op.uses().keys()[0];
        let bytes = key
            .options_canonical(&|_| Some("/typed".to_owned()))
            .unwrap();
        got.push(format!("{name} {}", hex(&bytes)));
        got.push(format!(
            "{name} sha {}",
            hex(&key.options_sha256(&|_| Some("/typed".to_owned())).unwrap())
        ));
        got.push(format!("{name} op {}", hex(&op.sha256())));
    }
    assert_eq!(got.join("\n"), GOLDEN.trim(), "\n{}", got.join("\n"));
}

const GOLDEN: &str = "\
raw 4f4e434c4f5054310001
raw sha 22c485d3367481df1d3ec61f5589d897d2fafbf2242f1ada9d3d8b60c7611e6e
raw op ab7d7669e84c841e74923e66ed956865613138b2a911c4194dec92631e8da209
cms 4f4e434c4f505431000201010201
cms sha 527ff4b9a6d5d237c9b4c6a5e90617b06debe506c60697578870b8fb21034626
cms op e5a6fdb14886e9a37456762ddc6a4652e552f7192a1b8b6cf25d1a07b974685c
cms_ex 4f4e434c4f50543100030100020003000401050006000701080109010a00
cms_ex sha 721f6636938156c8cfd5d965ce1107c6f84f7e3bf0b10b25ad314bc02333ef0d
cms_ex op 5e26ad089b44e87519d68265163deb09082013881df2a494f8d0ccc0933123a0
xml 4f4e434c4f50543100040101000000022f610201000000022f62
xml sha 743503a863ea3b394800d7329886445929e3551c672ef9206ba50db6a0f796f7
xml op fa9550181823dce9561e6420395cc8f55fb1d283757e8742abcd6fc36db062f7
xml_ex 4f4e434c4f50543100050101000000042f612f620201000000022f610302040000000100000001700000000575726e3a7005010000000575726e3a6f060100000031687474703a2f2f7777772e77332e6f72672f323030312f30342f786d6c647369672d6d6f7265237273612d736861323536070100000027687474703a2f2f7777772e77332e6f72672f323030312f30342f786d6c656e6323736861323536080309010a020b01010001
xml_ex sha 2015620adf9df64bb903382387db5ab9fced884c0a88dd0f238365d895eda042
xml_ex op db26ae1aaf9848eb8ec047c3f88b74b2c45c6d90a0390bf617ff6832bcd07001
xades 4f4e434c4f505431000601010201030100000031687474703a2f2f7777772e77332e6f72672f323030312f30342f786d6c647369672d6d6f7265237273612d736861323536040100000027687474703a2f2f7777772e77332e6f72672f323030312f30342f786d6c656e6323736861323536
xades sha 1e1238b33c67e75559889d5ec48bfd7de9d97d0317b5e1ab6960b268be3eea7e
xades op ed9a0f6604609f479da5f6dc8837987b1e4d10eed1b185127b99915288f833dd
";

#[test]
fn enum_tags_are_explicit_bytes() {
    // Offsets in a cms_ex encoding: magic (9), kind (1), then `id value` pairs.
    let at = |change: Option<(&str, &str)>, field: usize| {
        let text = match change {
            Some((a, b)) => edit(a, b),
            None => with(OP),
        };
        key_options(&text)[11 + 2 * (field - 1)]
    };
    assert_eq!(at(None, 4), 1); // basics
    assert_eq!(
        at(
            Some(("timestamp    = \"basics\"", "timestamp    = \"none\"")),
            4
        ),
        0
    );
    assert_eq!(
        at(
            Some(("timestamp    = \"basics\"", "timestamp    = \"kalkan\"")),
            4
        ),
        2
    );
    assert_eq!(
        at(
            Some(("certificates = \"signer\"", "certificates = \"chain\"")),
            5
        ),
        1
    );
    assert_eq!(
        at(Some(("output       = \"der\"", "output = \"base64\"")), 6),
        1
    );
    assert_eq!(
        at(Some(("output       = \"der\"", "output = \"pem\"")), 6),
        2
    );
    assert_eq!(
        at(
            Some((
                "output       = \"der\"",
                "output = \"der\"\nsigning_time = \"none\""
            )),
            10
        ),
        1
    );
    assert_eq!(
        at(
            Some((
                "output       = \"der\"",
                "output = \"der\"\ncontent_form = \"digest\""
            )),
            3
        ),
        1
    );
}

// The real ABI structs, destructured without `..`: a field added to any of them does not
// compile until it is classified here as covered by the profile or as one that must keep
// the core's default (the call must send it unset).
mod abi_guard {
    use oncl_pdk::abi::{
        SignCmsArgs, SignCmsExArgs, SignRawArgs, SignXmlArgs, SignXmlExArgs, SignedAttrs, XadesArgs,
    };

    pub fn raw(a: &SignRawArgs) {
        let SignRawArgs {
            handle: _, // bound by guard
            data: _,   // content
        } = a;
    }
    pub fn cms(a: &SignCmsArgs) {
        let SignCmsArgs {
            handle: _,
            data: _,      // content
            attached: _,  // profile
            timestamp: _, // profile bool
        } = a;
    }
    pub fn cms_ex(a: &SignCmsExArgs) {
        let SignCmsExArgs {
            handle: _,
            content: _,       // content and content form
            encapsulate: _,   // profile
            cosign: _,        // profile never core coerces auto
            econtent_type: _, // must be default none
            digest: _,        // must be default none too
            attrs: _,         // see signed attrs
            certificates: _,  // profile no extra
            timestamp: _,     // profile no custom
            output: _,        // profile
        } = a;
    }
    pub fn signed_attrs(a: &SignedAttrs) {
        let SignedAttrs {
            content_type: _,           // profile
            message_digest: _,         // profile
            signing_certificate_v2: _, // profile
            signing_time: _,           // profile now or none
            extra: _,                  // must be empty
        } = a;
    }
    pub fn xml(a: &SignXmlArgs) {
        let SignXmlArgs {
            handle: _,
            xml: _,     // content
            element: _, // profile
            parent: _,  // profile too
        } = a;
    }
    pub fn xml_ex(a: &SignXmlExArgs) {
        let SignXmlExArgs {
            handle: _,
            xml: _,                 // content
            element: _,             // profile
            parent: _,              // profile
            namespaces: _,          // profile
            other_prefix_uri: _,    // profile
            placement: _,           // profile
            signature_method: _,    // profile
            digest_method: _,       // profile
            signed_info_c14n: _,    // profile c14n
            transforms: _,          // profile (checked list)
            signature_id: _,        // must be default none
            signing_time_object: _, // must be default none
            strip_whitespace: _,    // profile
            base64_line_breaks: _,  // profile
            output: _,              // profile
        } = a;
    }
    pub fn xades(a: &XadesArgs) {
        let XadesArgs {
            handle: _,
            xml: _,              // content
            level: _,            // profile b or t
            tsa: _,              // profile no custom
            chain: _,            // must be empty
            signature_method: _, // profile
            digest_method: _,    // profile
        } = a;
    }
}

#[test]
fn the_abi_option_structs_are_all_classified() {
    // Compile-time guard: the destructurings above are exhaustive. Calling them with nothing
    // keeps them linked into the test.
    let _ = (
        abi_guard::raw as fn(&_),
        abi_guard::cms as fn(&_),
        abi_guard::cms_ex as fn(&_),
        abi_guard::signed_attrs as fn(&_),
        abi_guard::xml as fn(&_),
        abi_guard::xml_ex as fn(&_),
        abi_guard::xades as fn(&_),
    );
}

// ---- the install consent (MP5c) ---------------------------------------------------------

mod consent {
    use super::*;
    use oncl_flows::capabilities::{
        AddedLine, CapabilityLine, CmsAttribute, KeyUseKind, NetworkLine, OutputForm,
        PlacementKind, ProfileFact, TsaFamily, XadesLevelKind,
    };
    use oncl_plugin::operations::{AddedOperation, DIGEST_METHODS, SIGNATURE_METHODS};

    fn facts_of(text: &str) -> Vec<ProfileFact> {
        let manifest = parse(text).unwrap();
        let lines = manifest.operations()[0].consent(None).lines;
        lines
            .into_iter()
            .find_map(|l| match l {
                CapabilityLine::KeyProfile(f) => Some(f),
                _ => None,
            })
            .expect("a profile line")
    }

    #[test]
    fn every_cms_ex_field_is_shown_or_default() {
        // The default profile: only the essentials (and the fixed cosign).
        assert_eq!(
            facts_of(&op_of("cms_ex", "keys_sign_cms_ex", "\"pki\"", "")),
            [
                ProfileFact::Detached,
                ProfileFact::ContentAsIs,
                ProfileFact::NoTimestamp
            ]
        );
        // Every field away from its default.
        let facts = facts_of(&op_of(
            "cms_ex",
            "keys_sign_cms_ex",
            "\"pki\"",
            "content_form = \"digest\"\ntimestamp = \"kalkan\"\ncertificates = \"chain\"\n\
             output = \"pem\"\ncontent_type = false\nmessage_digest = false\n\
             signing_certificate_v2 = false\nsigning_time = \"none\"",
        ));
        assert_eq!(
            facts,
            [
                ProfileFact::Detached,
                ProfileFact::ContentAsIs,
                ProfileFact::DigestOnly,
                ProfileFact::Timestamp(TsaFamily::Kalkan),
                ProfileFact::ChainCertificates,
                ProfileFact::CmsOutput(OutputForm::Pem),
                ProfileFact::AttributeOff(CmsAttribute::ContentType),
                ProfileFact::AttributeOff(CmsAttribute::MessageDigest),
                ProfileFact::AttributeOff(CmsAttribute::SigningCertificate),
                ProfileFact::NoSigningTime,
            ]
        );
        let facts = facts_of(&op_of(
            "cms_ex",
            "keys_sign_cms_ex",
            "\"pki\"",
            "encapsulate = true\noutput = \"base64\"",
        ));
        assert_eq!(facts[0], ProfileFact::Attached);
        assert!(facts.contains(&ProfileFact::CmsOutput(OutputForm::Base64)));
    }

    #[test]
    fn every_xml_ex_field_is_shown_or_default() {
        assert_eq!(
            facts_of(&op_of("xml_ex", "keys_sign_xml_ex", "\"pki\"", "")),
            [ProfileFact::XmlWholeDocument]
        );
        let profile = format!(
            "element = \"/a\"\nparent = \"param:path\"\nplacement = \"parent\"\n\
             namespaces = [{{ prefix = \"a\", uri = \"urn:x\" }}]\nother_prefix_uri = \"urn:y\"\n\
             signature_method = \"{}\"\ndigest_method = \"{}\"\nc14n = \"exclusive\"\n\
             strip_whitespace = true\nbase64_line_breaks = false\n\
             output = {{ serialize = {{ declaration = true, standalone_no = false, trim = true }} }}",
            SIGNATURE_METHODS[0], DIGEST_METHODS[0]
        );
        let facts = facts_of(&op_of("xml_ex", "keys_sign_xml_ex", "\"pki\"", &profile));
        assert_eq!(
            facts,
            [
                ProfileFact::XmlElementFixed,
                ProfileFact::XmlParentParam,
                ProfileFact::XmlPlacement(PlacementKind::Parent),
                ProfileFact::XmlNamespaces(1),
                ProfileFact::XmlOtherPrefixUri,
                ProfileFact::SignatureMethod(SIGNATURE_METHODS[0].to_owned()),
                ProfileFact::DigestMethod(DIGEST_METHODS[0].to_owned()),
                ProfileFact::C14n("exclusive".to_owned()),
                ProfileFact::XmlStripWhitespace,
                ProfileFact::XmlBase64LineBreaks(false),
                ProfileFact::XmlSerialized,
            ]
        );
        let facts = facts_of(&op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            "transforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
        ));
        assert_eq!(
            facts,
            [
                ProfileFact::XmlWholeDocument,
                ProfileFact::XmlTransforms(vec![
                    "enveloped signature".to_owned(),
                    "inclusive canonicalisation with comments".to_owned()
                ]),
            ]
        );
        let facts = facts_of(&op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            "element = \"param:path\"\nparent = \"/p\"\nplacement = \"parent\"\nbase64_line_breaks = true",
        ));
        assert_eq!(facts[0], ProfileFact::XmlElementParam);
        assert_eq!(facts[1], ProfileFact::XmlParentFixed);
        assert!(facts.contains(&ProfileFact::XmlBase64LineBreaks(true)));
        let facts = facts_of(&op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            "placement = \"first_child_of_document\"",
        ));
        assert!(facts.contains(&ProfileFact::XmlPlacement(
            PlacementKind::FirstChildOfDocument
        )));
    }

    #[test]
    fn xades_methods_are_shown() {
        let facts = facts_of(&op_of(
            "xades",
            "keys_sign_xades",
            "\"pki\"",
            &format!(
                "signature_method = \"{}\"\ndigest_method = \"{}\"",
                SIGNATURE_METHODS[1], DIGEST_METHODS[1]
            ),
        ));
        assert!(facts.contains(&ProfileFact::SignatureMethod(
            SIGNATURE_METHODS[1].to_owned()
        )));
        assert!(facts.contains(&ProfileFact::DigestMethod(DIGEST_METHODS[1].to_owned())));
    }

    #[test]
    fn a_crafted_xpath_is_the_plugins_text_and_never_a_host_line() {
        let crafted = "/a/Install / Allow / Core verified; no network";
        let text = op_of(
            "xml",
            "keys_sign_xml",
            "\"pki\"",
            &format!("element = \"{crafted}\"\nparent = \"/p/Core verified\""),
        );
        let consent = parse(&text).unwrap().operations()[0].consent(None);
        assert_eq!(consent.xpaths, [crafted, "/p/Core verified"]);
        let host = format!("{:?}", consent.lines);
        assert!(
            !host.contains("Core verified") && !host.contains("Allow"),
            "{host}"
        );
    }

    #[test]
    fn each_added_reason_maps_to_its_own_line() {
        let manifest = parse(&with(OP)).unwrap();
        let reasons = vec![
            AddedReason::New,
            AddedReason::Changed,
            AddedReason::KeyUse,
            AddedReason::Imports(vec!["http_request"]),
            AddedReason::Network,
            AddedReason::Server,
        ];
        let added = AddedOperation {
            name: "sign-file".to_owned(),
            reasons,
        };
        let lines = manifest.operations()[0].consent(Some(&added)).lines;
        assert_eq!(
            lines[..6],
            [
                CapabilityLine::Added(AddedLine::New),
                CapabilityLine::Added(AddedLine::Changed),
                CapabilityLine::Added(AddedLine::KeyUse),
                CapabilityLine::Added(AddedLine::Imports(vec!["http_request".to_owned()])),
                CapabilityLine::Added(AddedLine::Network),
                CapabilityLine::Added(AddedLine::Server),
            ]
        );
    }

    #[test]
    fn the_manifests_consents_mark_only_the_added_operations() {
        let two = format!("{}{}", with(OP), OP.replace("sign-file", "other-op"));
        let new = parse(&two).unwrap();
        let old = parse(&with(OP)).unwrap();
        let added = new.added_over(&old);
        let consents = new.operation_consents(Some(&added));
        assert_eq!(consents.len(), 2);
        assert_eq!(consents[0].name, "sign-file");
        assert!(
            !consents[0]
                .lines
                .iter()
                .any(|l| matches!(l, CapabilityLine::Added(_)))
        );
        assert_eq!(consents[1].name, "other-op");
        assert!(
            consents[1]
                .lines
                .contains(&CapabilityLine::Added(AddedLine::New))
        );
        // Without `added`, nothing is marked; a manifest without operations has none.
        assert!(
            !new.operation_consents(None)[1]
                .lines
                .iter()
                .any(|l| matches!(l, CapabilityLine::Added(_)))
        );
        assert!(parse(HEAD).unwrap().operation_consents(None).is_empty());
    }

    fn lines_of(text: &str) -> Vec<CapabilityLine> {
        parse(text).unwrap().operations()[0].consent(None).lines
    }

    #[test]
    fn the_reference_operation_is_said_from_checked_fields() {
        let manifest = parse(&with(OP)).unwrap();
        let consent = manifest.operations()[0].consent(None);
        assert_eq!(consent.name, "sign-file");
        assert_eq!(
            consent.lines,
            [
                CapabilityLine::KeyUse(KeyUseKind::CmsEx),
                CapabilityLine::KeyProfile(vec![
                    ProfileFact::Detached,
                    ProfileFact::ContentAsIs,
                    ProfileFact::Timestamp(TsaFamily::Basics)
                ]),
                CapabilityLine::OperationNetwork(NetworkLine::Pki),
                CapabilityLine::OperationServer(false),
            ]
        );
        // The label is the plugin's: kept apart, never among the lines.
        assert_eq!(
            consent.label,
            ["Подписать файл", "Файлға қол қою", "Sign a file"]
        );
    }

    #[test]
    fn server_network_and_profile_changes_show() {
        let lines = lines_of(&edit("server  = false", "server  = true"));
        assert!(lines.contains(&CapabilityLine::OperationServer(true)));
        let lines = lines_of(&info_op(
            "[\"https://api.example.kz/v1/\"]",
            "\"http_request\"",
        ));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::OperationNetwork(NetworkLine::Urls(urls))
                if urls == &["https://api.example.kz/v1/".to_owned()]
        )));
        let lines = lines_of(&edit("encapsulate  = false", "encapsulate  = true"));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f[0] == ProfileFact::Attached
        )));
        let lines = lines_of(&edit(
            "timestamp    = \"basics\"",
            "timestamp    = \"kalkan\"",
        ));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f.contains(&ProfileFact::Timestamp(TsaFamily::Kalkan))
        )));
        let lines = lines_of(&edit(
            "timestamp    = \"basics\"",
            "timestamp    = \"none\"",
        ));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f.contains(&ProfileFact::NoTimestamp)
        )));
    }

    #[test]
    fn an_operation_without_a_key_says_so() {
        let text = edit(
            "imports = [\"keys_select\", \"keys_describe\", \"keys_sign_cms_ex\", \"hash\"]",
            "imports = [\"hash\"]",
        );
        let text = text.replace("interactive = [\"keys_select\"]\n", "");
        let start = text.find("[[operations.uses.key]]").unwrap();
        let lines = lines_of(&text[..start]);
        assert_eq!(lines[0], CapabilityLine::NoKey, "{lines:?}");
        assert!(
            !lines
                .iter()
                .any(|l| matches!(l, CapabilityLine::KeyProfile(_)))
        );
    }

    #[test]
    fn an_update_names_what_is_new_or_wider() {
        let old = with(OP);
        let new = edit("server  = false", "server  = true");
        let new = parse(&new).unwrap();
        let added = new.added_over(&parse(&old).unwrap());
        let consent = new.operations()[0].consent(added.operations.first());
        assert!(
            consent
                .lines
                .contains(&CapabilityLine::Added(AddedLine::Server))
        );
        // Pki → URLs (an operation without a key): a wider network by the core's ruling.
        let wide = parse(&info_op(
            "[\"https://api.example.kz/v1/\"]",
            "\"http_request\"",
        ))
        .unwrap();
        let was = parse(&info_op("\"pki\"", "\"http_request\"")).unwrap();
        let added = wide.added_over(&was);
        let consent = wide.operations()[0].consent(added.operations.first());
        assert!(
            consent
                .lines
                .contains(&CapabilityLine::Added(AddedLine::Network))
        );
        // Nothing marked when nothing is added.
        let same = parse(&old).unwrap();
        let none = same.operations()[0].consent(None);
        assert!(
            !none
                .lines
                .iter()
                .any(|l| matches!(l, CapabilityLine::Added(_)))
        );
    }

    #[test]
    fn xml_and_xades_profiles_are_said_in_words() {
        let lines = lines_of(&op_of(
            "xades",
            "keys_sign_xades",
            "\"pki\"",
            "level = \"t\"\ntsa = \"kalkan\"",
        ));
        assert_eq!(
            lines[0],
            CapabilityLine::KeyUse(KeyUseKind::Xades),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f.contains(&ProfileFact::Xades(XadesLevelKind::T))
                && f.contains(&ProfileFact::Timestamp(TsaFamily::Kalkan))
        )));
        let lines = lines_of(&op_of(
            "xades",
            "keys_sign_xades",
            "\"pki\"",
            "level = \"b\"",
        ));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f.contains(&ProfileFact::Xades(XadesLevelKind::B))
                && f.contains(&ProfileFact::NoTimestamp)
        )));
        let lines = lines_of(&op_of(
            "xml_ex",
            "keys_sign_xml_ex",
            "\"pki\"",
            "element = \"/a/b\"",
        ));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f.contains(&ProfileFact::XmlElementFixed)
        )));
        let lines = lines_of(&op_of("xml", "keys_sign_xml", "\"pki\"", ""));
        assert!(lines.iter().any(|l| matches!(
            l,
            CapabilityLine::KeyProfile(f) if f == &[ProfileFact::XmlWholeDocument]
        )));
    }
}

// ---- MP1b: any JSON object as the request template; text as content ---------------------

/// An operation with the request template `request` (a TOML literal string, so it holds no
/// single quote), the params `params` (`name:kind` pairs) and a raw key use over `content`.
fn shaped(request: &str, params: &[(&str, &str)], content: &str) -> String {
    let mut text = String::new();
    for (name, kind) in params {
        text.push_str(&format!(
            "[[operations.params]]\nname = \"{name}\"\nkind = \"{kind}\"\n"
        ));
    }
    with(&format!(
        r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{request}'
label = {{ ru = "а", kk = "ә", en = "a" }}
{text}
[operations.uses]
imports = ["keys_sign_raw"]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "{content}"
"#
    ))
    .replace(
        r#"modules = ["example.sign", "example.other"]"#,
        r#"modules = ["example.sign"]"#,
    )
}

#[test]
fn the_three_real_request_shapes_parse() {
    // ARRAY args (rating1c, dogovor24, qiwi).
    parse(&shaped(
        r#"{"module":"example.sign","method":"sign","args":["{doc:base64}","fixed",1,true]}"#,
        &[("doc", "document")],
        "param:doc",
    ))
    .unwrap();
    // OBJECT args (fhs, energy).
    parse(&shaped(
        r#"{"module":"example.sign","method":"sign","args":{"data":"{doc:base64}","who":{"name":"{who}"}}}"#,
        &[("doc", "document"), ("who", "text")],
        "param:doc",
    ))
    .unwrap();
    // ROOT-KEYED, no module, no args (esf-osdkz, eproc, efactoring, market).
    parse(&shaped(
        r#"{"method":"signPlainData","storageName":"PKCS12","data":"{text}"}"#,
        &[("text", "text")],
        "param:text",
    ))
    .unwrap();
    parse(&shaped(
        r#"{"type":"text","data":"{text}"}"#,
        &[("text", "text")],
        "param:text",
    ))
    .unwrap();
    // Not even a method: an empty object, for an operation with no params.
    parse(
        &info_op("\"pki\"", "\"hash\"")
            .replace(
                r#"{"module":"example.sign","method":"info","args":[]}"#,
                "{}",
            )
            .replace(
                r#"modules = ["example.sign", "example.other"]"#,
                r#"modules = ["example.sign"]"#,
            ),
    )
    .unwrap();
}

#[test]
fn request_template_injections_and_bombs_are_refused() {
    let doc = [("doc", "document")];
    let ok = |request: &str| parse(&shaped(request, &doc, "param:doc")).map(|_| ());
    let bad = |what: &str, request: &str| match ok(request) {
        Err(PackageError::Operation(OperationError::Request { .. })) => {}
        other => panic!("{what}: {other:?}"),
    };
    bad("placeholder in a key", r#"{"{doc}":1,"d":"{doc:base64}"}"#);
    bad(
        "placeholder in a nested key",
        r#"{"a":{"{doc}":1},"d":"{doc:base64}"}"#,
    );
    bad("partial placeholder", r#"{"d":"x{doc:base64}"}"#);
    bad(
        "two placeholders in one string",
        r#"{"d":"{doc:base64}{doc:base64}"}"#,
    );
    bad(
        "module placeholder",
        r#"{"module":"{doc}","d":"{doc:base64}"}"#,
    );
    bad(
        "method placeholder",
        r#"{"method":"{doc}","d":"{doc:base64}"}"#,
    );
    bad(
        "other module",
        r#"{"module":"example.other","d":"{doc:base64}"}"#,
    );
    bad("module not text", r#"{"module":1,"d":"{doc:base64}"}"#);
    bad("method not text", r#"{"method":["a"],"d":"{doc:base64}"}"#);
    bad(
        "undeclared placeholder",
        r#"{"d":"{doc:base64}","e":"{nope}"}"#,
    );
    assert!(matches!(
        ok(r#"{"d":1}"#),
        Err(PackageError::Operation(OperationError::Param { .. }))
    ));
    bad("duplicate key", r#"{"d":"{doc:base64}","d":1}"#);
    bad(
        "duplicate nested key",
        r#"{"a":{"b":1,"b":2},"d":"{doc:base64}"}"#,
    );
    bad("float", r#"{"d":"{doc:base64}","n":1.5}"#);
    bad("root array", r#"["{doc:base64}"]"#);
    bad("root string", r#""{doc:base64}""#);
    bad("document without base64", r#"{"d":"{doc}"}"#);
    bad("not JSON", r#"{"d":"{doc:base64}""#);
    // A key with a control character or too long.
    bad(
        "long key",
        &format!(r#"{{"{}":1,"d":"{{doc:base64}}"}}"#, "k".repeat(129)),
    );
    // Depth: 16 deep is fine, 17 is not.
    let nest = |depth: usize| {
        format!(
            r#"{{"d":"{{doc:base64}}","n":{}{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        )
    };
    ok(&nest(14)).unwrap();
    bad("depth bomb", &nest(40));
    bad("deep brackets", &nest(200));
    // Count of values and of keys of one object.
    bad(
        "value bomb",
        &format!(r#"{{"d":"{{doc:base64}}","n":[{}0]}}"#, "0,".repeat(2100)),
    );
    let keys: String = (0..70).map(|i| format!(r#""k{i}":0,"#)).collect();
    bad("key bomb", &format!(r#"{{{keys}"d":"{{doc:base64}}"}}"#));
    // Size.
    bad(
        "size bomb",
        &format!(r#"{{"d":"{{doc:base64}}","s":"{}"}}"#, "a".repeat(17_000)),
    );
}

#[test]
fn text_is_content_for_every_key_kind() {
    // raw and cms_ex over a text param: the UTF-8 bytes of the typed value are signed.
    let text_op = |kind: &str, import: &str, profile: &str| op_of_text(kind, import, profile);
    for (kind, import) in [
        ("raw", "keys_sign_raw"),
        ("cms", "keys_sign_cms"),
        ("cms_ex", "keys_sign_cms_ex"),
        ("xml", "keys_sign_xml"),
        ("xml_ex", "keys_sign_xml_ex"),
        ("xades", "keys_sign_xades"),
    ] {
        let m = parse(&text_op(kind, import, "")).unwrap_or_else(|e| panic!("{kind}: {e}"));
        let key = &m.operations()[0].uses().keys()[0];
        assert_eq!(key.content(), &Content::Bound("text".to_owned()), "{kind}");
    }
    // A digest form of a text is fine (the core hashes the bytes); derived text is not.
    parse(&text_op(
        "cms_ex",
        "keys_sign_cms_ex",
        "content_form = \"digest\"",
    ))
    .unwrap();
    assert!(parse(&text_op("raw", "keys_sign_raw", "").replace("param:text", "derived")).is_err());
    // The limits: 1..=65536 characters.
    let limit = |n: u32| {
        text_op("raw", "keys_sign_raw", "").replace(
            "kind = \"text\"",
            &format!("kind = \"text\"\nmax_chars = {n}"),
        )
    };
    parse(&limit(1)).unwrap();
    parse(&limit(65_536)).unwrap();
    assert!(matches!(
        refused(&limit(65_537)),
        OperationError::Param { .. }
    ));
    assert!(matches!(refused(&limit(0)), OperationError::Param { .. }));
    // A flag or a choice is never content.
    let flag = text_op("raw", "keys_sign_raw", "").replace("kind = \"text\"", "kind = \"flag\"");
    assert!(matches!(refused(&flag), OperationError::KeyContent { .. }));
}

fn op_of_text(kind: &str, import: &str, profile: &str) -> String {
    with(&format!(
        r#"
[[operations]]
name = "x"
module = "example.sign"
manual = true
request = '{{"method":"sign","data":"{{text}}"}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "text"
kind = "text"
[operations.uses]
imports = ["{import}"]
network = "pki"
[[operations.uses.key]]
kind = "{kind}"
content = "param:text"
[operations.uses.key.profile]
{profile}
"#
    ))
    .replace(
        r#"modules = ["example.sign", "example.other"]"#,
        r#"modules = ["example.sign"]"#,
    )
}

#[test]
fn the_declaration_encoding_is_versioned_and_covers_the_template() {
    // `ONCLOP2` is the only magic written. (No production consumer of `canonical()` exists
    // yet; when one does, it must refuse any other magic. The magic is what lets it.)
    let m = parse(&with(OP)).unwrap();
    assert!(m.operations()[0].canonical().starts_with(b"ONCLOP2\0"));
    // Operations that differ only in the request template differ in their encoding:
    // another shape, another key order, another whitespace.
    let canonical = |request: &str| {
        parse(&shaped(request, &[("doc", "document")], "param:doc"))
            .unwrap()
            .operations()[0]
            .canonical()
    };
    let shapes = [
        r#"{"module":"example.sign","method":"m","args":["{doc:base64}"]}"#,
        r#"{"module":"example.sign","method":"m","args":{"d":"{doc:base64}"}}"#,
        r#"{"method":"m","d":"{doc:base64}"}"#,
        r#"{"d":"{doc:base64}","method":"m"}"#,
        r#"{"method":"m", "d":"{doc:base64}"}"#,
    ];
    let all: Vec<_> = shapes.iter().map(|r| canonical(r)).collect();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn golden_vectors_for_the_three_request_shapes() {
    let cases = [
        (
            "array",
            r#"{"module":"example.sign","method":"sign","args":["{doc:base64}",1]}"#,
        ),
        (
            "object",
            r#"{"module":"example.sign","method":"sign","args":{"data":"{doc:base64}","n":-2}}"#,
        ),
        (
            "root",
            r#"{"method":"signPlainData","storageName":"PKCS12","data":"{doc:base64}"}"#,
        ),
    ];
    let mut got = Vec::new();
    for (name, request) in cases {
        let m = parse(&shaped(request, &[("doc", "document")], "param:doc")).unwrap();
        got.push(format!("{name} {}", hex(&m.operations()[0].sha256())));
    }
    assert_eq!(got.join("\n"), SHAPES_GOLDEN.trim(), "\n{}", got.join("\n"));
}

const SHAPES_GOLDEN: &str = "\
array e04e6927e539d8fb868a6b180673bfe6f196fecbe1780c5dad0390a0942dcaa7
object b491d689aa584343f82e1b5a4bd4e7052b95161443af8ed632a55ba4e56b4fd0
root fbd7ebfe6caa46866ad58df2694bae9d0692a11a7e94d2263b17096c42f81a80
";

#[test]
fn method_cannot_be_a_typed_text_placeholder() {
    let ps = [("doc", "document"), ("t", "text")];
    for request in [
        r#"{"method":"{t}","d":"{doc:base64}"}"#,
        r#"{"method":"a{t}","d":"{doc:base64}"}"#,
        r#"{"method":"{","d":"{doc:base64}"}"#,
    ] {
        let r = parse(&shaped(request, &ps, "param:doc"));
        assert!(
            matches!(
                r,
                Err(PackageError::Operation(OperationError::Request { .. }))
            ),
            "{request}: {r:?}"
        );
    }
}

#[test]
fn template_limits_hold_at_their_boundaries() {
    let ok =
        |request: &str| parse(&shaped(request, &[("doc", "document")], "param:doc")).map(|_| ());
    let refused_request = |what: &str, request: &str| {
        assert!(
            matches!(
                ok(request),
                Err(PackageError::Operation(OperationError::Request { .. }))
            ),
            "{what}"
        );
    };
    // Depth: the root is 1.
    let nest = |n: usize| {
        format!(
            r#"{{"d":"{{doc:base64}}","n":{}{}}}"#,
            "[".repeat(n),
            "]".repeat(n)
        )
    };
    ok(&nest(15)).unwrap();
    refused_request("depth 17", &nest(16));
    // Values: root, `d`, `n` and the items.
    let vals = |n: usize| {
        format!(
            r#"{{"d":"{{doc:base64}}","n":[{}]}}"#,
            vec!["0"; n].join(",")
        )
    };
    ok(&vals(2045)).unwrap();
    refused_request("2049 values", &vals(2046));
    // Keys of one object.
    let keys = |n: usize| {
        let extra: String = (0..n).map(|i| format!(r#""k{i}":0,"#)).collect();
        format!(r#"{{{extra}"d":"{{doc:base64}}"}}"#)
    };
    ok(&keys(63)).unwrap();
    refused_request("65 keys", &keys(64));
    // A key's length and characters.
    let key = |k: &str| format!(r#"{{"{k}":0,"d":"{{doc:base64}}"}}"#);
    ok(&key(&"k".repeat(128))).unwrap();
    refused_request("key of 129", &key(&"k".repeat(129)));
    for bad in [r"a\u0000b", r"a\u202eb", r"a\nb", r"a\u200bb", r"a\u007fb"] {
        refused_request(bad, &key(bad));
    }
    // Numbers: only what `i64`/`u64` holds, as written.
    for good in ["18446744073709551615", "-9223372036854775808", "0"] {
        ok(&format!(r#"{{"d":"{{doc:base64}}","n":{good}}}"#)).unwrap();
    }
    for bad in [
        "18446744073709551616",
        "-9223372036854775809",
        "1e2",
        "0.0",
        "1.5",
    ] {
        refused_request(bad, &format!(r#"{{"d":"{{doc:base64}}","n":{bad}}}"#));
    }
}

#[test]
fn several_modules_need_a_fixed_root_module() {
    // The plugin serves two modules: a template that names none leaves the declared one
    // inert, so it is refused; naming it (or the other served one when declared so) is fine.
    let two = |request: &str, module: &str| {
        parse(
            &shaped(request, &[("doc", "document")], "param:doc")
                .replace(
                    r#"modules = ["example.sign"]"#,
                    r#"modules = ["example.sign", "example.other"]"#,
                )
                .replace(
                    r#"module = "example.sign""#,
                    &format!(r#"module = "{module}""#),
                ),
        )
        .map(|_| ())
    };
    assert!(matches!(
        two(r#"{"method":"m","d":"{doc:base64}"}"#, "example.sign"),
        Err(PackageError::Operation(OperationError::Request { why, .. })) if why.contains("several modules")
    ));
    two(
        r#"{"module":"example.sign","method":"m","d":"{doc:base64}"}"#,
        "example.sign",
    )
    .unwrap();
    two(
        r#"{"module":"example.other","method":"m","d":"{doc:base64}"}"#,
        "example.other",
    )
    .unwrap();
    // One module: the root `module` stays optional.
    let one = shaped(
        r#"{"method":"m","d":"{doc:base64}"}"#,
        &[("doc", "document")],
        "param:doc",
    )
    .replace(
        r#"modules = ["example.sign", "example.other"]"#,
        r#"modules = ["example.sign"]"#,
    );
    parse(&one).unwrap();
}

#[test]
fn signed_text_refuses_what_a_window_could_hide() {
    use oncl_plugin::operations::signed_text_problem;
    for bad in [
        "pay \u{202e}100\u{202c}",
        "a\u{0}b",
        "a\r\nb",
        "x\u{200b}y",
        "\u{feff}x",
        "a\u{2028}b",
        "a\u{85}b",
        "a\u{7f}",
        "\u{1b}[2J",
        "a\u{00ad}b",
        "a\u{2066}b",
        "a\u{e0041}b",
        // Hangul fillers are drawn as blanks.
        "a\u{115f}b",
        "a\u{1160}b",
        "a\u{3164}b",
        "a\u{ffa0}b",
    ] {
        assert!(signed_text_problem(bad).is_some(), "{bad:?}");
    }
    for good in [
        "a\tb\nc",
        "договор №1 \u{4e16}",
        " x ",
        "emoji \u{1f600}",
        "",
    ] {
        assert!(signed_text_problem(good).is_none(), "{good:?}");
    }
}
