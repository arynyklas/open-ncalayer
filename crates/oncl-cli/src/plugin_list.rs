//! `oncl plugin operations`: what a plugin manifest declares, so an operator can write
//! grants (`plugin call --operation … --allow-import …`) without reading the TOML. Nothing
//! is run, no key or engine is opened: the manifest (and with `--wasm` the module) is read
//! once, bounded, and checked by the library that also checks it for `plugin call`.
//!
//! The words of a key use and of the signature profile are the host's own (the install
//! window's English texts); the plugin's label is its own untrusted text and is shown quoted
//! and escaped.
use crate::{args::Cli, control::Control, output, plugin};
use clap::Args;
use oncl_core::OperationError;
use oncl_flows::{
    Locale,
    capabilities::{CapabilityLine, capability_text},
};
use oncl_pki::resource::{ProcessingError, ResourceLimits, SharedBudget};
use oncl_plugin::operations::{Content, Network, Operation, ParamKind};
use serde::Serialize;
use std::{fmt::Write as _, path::PathBuf, sync::Arc};

#[derive(Args)]
pub struct OperationsArgs {
    /// The plugin's `plugin.toml`.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Also compile this module against the manifest (the imports of every operation must be
    /// imports of the module, as `cargo xtask plugin-ops-check` requires); exit 1 if not.
    #[arg(long)]
    pub wasm: Option<PathBuf>,
}

#[derive(Serialize)]
struct Report {
    code: &'static str,
    applied: &'static str,
    plugin: Plugin,
    operations: Vec<Info>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<Module>,
}
#[derive(Serialize)]
struct Plugin {
    id: String,
    version: String,
}
#[derive(Serialize)]
struct Info {
    name: String,
    /// The plugin's own English label (untrusted text).
    label: String,
    server: bool,
    manual: bool,
    /// `false` for an operation with `derived` content, which no host runs yet.
    runnable: bool,
    derived: bool,
    /// Whether `plugin call` can run it: `server` and runnable.
    cli: bool,
    imports: Vec<&'static str>,
    network: Net,
    params: Vec<ParamInfo>,
    keys: Vec<KeyInfo>,
    /// The plugin's own XPaths of the profile (untrusted text).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xpaths: Vec<String>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Net {
    None,
    Pki,
    Urls { urls: Vec<String> },
}
#[derive(Serialize)]
struct ParamInfo {
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    choices: Option<Vec<String>>,
}
#[derive(Serialize)]
struct KeyInfo {
    /// `raw`, `cms`, `cms_ex`, `xml`, `xml_ex` or `xades`.
    kind: &'static str,
    /// `param:<name>` (the bytes of that parameter) or `derived` (computed by the plugin).
    content: String,
    /// What the key use is, in the host's words.
    words: String,
    /// The options the core forces, in the host's words (absent when there are none to say).
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}
#[derive(Serialize)]
struct Module {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn param_info(param: &oncl_plugin::operations::Param) -> ParamInfo {
    let mut info = ParamInfo {
        name: param.name.clone(),
        kind: "",
        max_bytes: None,
        max_chars: None,
        choices: None,
    };
    match &param.kind {
        ParamKind::Document { max_bytes } => {
            info.kind = "document";
            info.max_bytes = Some(*max_bytes);
        }
        ParamKind::Text { max_chars } => {
            info.kind = "text";
            info.max_chars = Some(*max_chars);
        }
        ParamKind::Choice { choices } => {
            info.kind = "choice";
            info.choices = Some(choices.clone());
        }
        ParamKind::Flag => info.kind = "flag",
        ParamKind::Locale => info.kind = "locale",
    }
    info
}

fn info(operation: &Operation) -> Info {
    let consent = operation.consent(None);
    // The consent says, per key use, the kind line and then (when it has facts) its profile.
    let mut keys: Vec<KeyInfo> = Vec::new();
    let mut declared = operation.uses().keys().iter();
    for line in &consent.lines {
        match line {
            CapabilityLine::KeyUse(_) => {
                if let Some(key) = declared.next() {
                    keys.push(KeyInfo {
                        kind: key.kind().as_str(),
                        content: match key.content() {
                            Content::Bound(param) => format!("param:{param}"),
                            Content::Derived => "derived".to_owned(),
                        },
                        words: capability_text(line, Locale::En),
                        profile: None,
                    });
                }
            }
            CapabilityLine::KeyProfile(_) => {
                if let Some(key) = keys.last_mut() {
                    key.profile = Some(capability_text(line, Locale::En));
                }
            }
            _ => {}
        }
    }
    Info {
        name: operation.name().to_owned(),
        label: operation.label().en.clone(),
        server: operation.server(),
        manual: operation.manual(),
        runnable: operation.runnable(),
        derived: operation.is_derived(),
        cli: operation.server() && operation.runnable(),
        imports: operation
            .uses()
            .imports()
            .iter()
            .map(|i| i.name())
            .collect(),
        network: match operation.uses().network() {
            Network::None => Net::None,
            Network::Pki => Net::Pki,
            Network::Urls(urls) => Net::Urls {
                urls: urls.iter().map(ToString::to_string).collect(),
            },
        },
        params: operation.params().iter().map(param_info).collect(),
        keys,
        xpaths: consent.xpaths,
    }
}

fn yes(on: bool) -> &'static str {
    if on { "yes" } else { "no" }
}

/// The operator's reading of the report. Plugin-supplied text is quoted with `{:?}`.
fn human(report: &Report) -> String {
    let mut out = String::new();
    let plugin = &report.plugin;
    if report.operations.is_empty() {
        let _ = write!(
            out,
            "plugin {} {} declares no operations: it runs only with a free --args-file and the grants are not checked against a declaration",
            plugin.id, plugin.version
        );
    } else {
        let _ = write!(
            out,
            "plugin {} {}: {} declared operation(s)",
            plugin.id,
            plugin.version,
            report.operations.len()
        );
    }
    for op in &report.operations {
        let _ = write!(out, "\noperation {}\n  label: {:?}", op.name, op.label);
        let _ = write!(
            out,
            "\n  server: {}  manual: {}",
            yes(op.server),
            yes(op.manual)
        );
        let runs = if op.derived {
            "no (not runnable: derived content)"
        } else if !op.server {
            "no (not for the CLI: server = false)"
        } else {
            "yes"
        };
        let _ = write!(out, "\n  cli: {runs}");
        let _ = write!(out, "\n  imports: {}", list(&op.imports));
        let _ = write!(
            out,
            "\n  network: {}",
            match &op.network {
                Net::None => "none".to_owned(),
                Net::Pki => "pki".to_owned(),
                Net::Urls { urls } => format!("urls {}", urls.join(", ")),
            }
        );
        if op.params.is_empty() {
            out.push_str("\n  params: none");
        }
        for param in &op.params {
            let _ = write!(out, "\n  param {}: {}", param.name, param.kind);
            if let Some(n) = param.max_bytes {
                let _ = write!(out, " (at most {n} bytes)");
            }
            if let Some(n) = param.max_chars {
                let _ = write!(out, " (at most {n} characters)");
            }
            if let Some(choices) = &param.choices {
                let _ = write!(out, " ({})", choices.join(" | "));
            }
        }
        if op.keys.is_empty() {
            out.push_str("\n  key: none");
        }
        for key in &op.keys {
            let _ = write!(out, "\n  key: {}, content {}", key.kind, key.content);
            let _ = write!(out, "\n    {}", key.words);
            if let Some(profile) = &key.profile {
                let _ = write!(out, "\n    {profile}");
            }
        }
        for xpath in &op.xpaths {
            let _ = write!(out, "\n  plugin's xpath: {xpath:?}");
        }
    }
    match &report.module {
        None => {}
        Some(Module { ok: true, .. }) => {
            out.push_str("\nmodule: ok (every operation's imports are imports of the module)");
        }
        Some(Module { error, .. }) => {
            let _ = write!(
                out,
                "\nmodule: FAILED: {:?}",
                error.as_deref().unwrap_or_default()
            );
        }
    }
    out
}
fn list(names: &[&str]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

/// Lists the declared operations of a manifest; exit 1 when `--wasm` does not fit it.
pub fn run(args: &OperationsArgs, cli: &Cli, control: &Control) -> Result<i32, OperationError> {
    let limits = ResourceLimits {
        operation_timeout: control.remaining()?,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits)?);
    let mut reservation = budget.reserve_configuration(0, 0)?;
    let manifest_bytes =
        plugin::read_bounded_file(&args.manifest, plugin::MANIFEST_BYTES, &mut reservation, 64)?;
    let text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| ProcessingError::InvalidInput("manifest is not UTF-8"))?;
    let manifest = oncl_plugin::Manifest::from_toml(text).map_err(|error| {
        // The operator's own file: say why, escaped (the text may quote the manifest).
        crate::diagnostic(format_args!(
            "oncl: invalid plugin manifest: {:?}",
            error.to_string()
        ));
        ProcessingError::InvalidInput("invalid plugin manifest")
    })?;
    let module = match &args.wasm {
        None => None,
        Some(path) => {
            let wasm = plugin::read_bounded_file(path, plugin::MODULE_BYTES, &mut reservation, 4)?;
            Some(match oncl_plugin::Engine::new().compile(&manifest, &wasm) {
                Ok(_) => Module {
                    ok: true,
                    error: None,
                },
                Err(error) => Module {
                    ok: false,
                    error: Some(error.to_string()),
                },
            })
        }
    };
    let failed = module.as_ref().is_some_and(|m| !m.ok);
    let report = Report {
        code: if failed { "InvalidInput" } else { "Completed" },
        applied: "NotApplied",
        plugin: Plugin {
            id: manifest.id.clone(),
            version: manifest.version.to_string(),
        },
        operations: manifest.operations().iter().map(info).collect(),
        module,
    };
    output::terminal(cli, &report, &human(&report))?;
    Ok(i32::from(failed))
}
