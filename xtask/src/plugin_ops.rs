//! `cargo xtask plugin-ops-check`: lints the `[[operations]]` of `plugin.toml` files.
//!
//! The manifest parser (`oncl_plugin::Manifest::from_toml`) owns every rule of the schema
//! (names, placeholders, labels, profiles, `max_uses`, content kinds, flags); this module
//! never restates them, it reports the parser's refusal under its rule name. What it adds:
//! the operations' imports against the compiled module's, and the summary.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context;
use oncl_plugin::operations::{Content, KeyKind, MAX_USES, OperationError};
use oncl_plugin::{Engine, Manifest, PackageError};
use serde_json::{Value, json};

/// Where `plugin pack` leaves a plugin crate's module, below the workspace root.
pub const WASM_DIR: &str = "target/plugin-build/wasm32-unknown-unknown/release";

/// What to check.
pub struct Options<'a> {
    /// `plugin.toml` files or plugin directories, besides `plugins/*`.
    pub extra: &'a [PathBuf],
    /// Where the built modules are.
    pub wasm_dir: &'a Path,
    /// A missing module is an error, not a warning.
    pub require_wasm: bool,
}

/// One problem: the rule it breaks and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub message: String,
}

/// The result for one manifest.
#[derive(Debug, Default)]
pub struct PluginReport {
    pub plugin: String,
    pub operations: usize,
    pub runnable: usize,
    pub derived: usize,
    pub errors: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub notices: Vec<String>,
}

impl PluginReport {
    pub fn status(&self) -> &'static str {
        if !self.errors.is_empty() {
            "error"
        } else if self.operations == 0 {
            "no operations"
        } else if self.derived > 0 {
            "blocked until MP3b"
        } else if !self.warnings.is_empty() {
            "ok (warnings)"
        } else {
            "ok"
        }
    }
}

/// All reports.
#[derive(Debug, Default)]
pub struct Report {
    pub plugins: Vec<PluginReport>,
}

impl Report {
    pub fn errors(&self) -> usize {
        self.plugins.iter().map(|p| p.errors.len()).sum()
    }

    /// The process exit code: 0 without errors, 1 with.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.errors() > 0)
    }

    pub fn to_json(&self) -> Value {
        let finding = |f: &Finding| json!({"rule": f.rule, "message": f.message});
        json!({
            "plugins": self.plugins.iter().map(|p| json!({
                "plugin": p.plugin,
                "operations": p.operations,
                "runnable": p.runnable,
                "derived": p.derived,
                "status": p.status(),
                "errors": p.errors.iter().map(finding).collect::<Vec<_>>(),
                "warnings": p.warnings.iter().map(finding).collect::<Vec<_>>(),
                "notices": p.notices,
            })).collect::<Vec<_>>(),
            "errors": self.errors(),
            "exit_code": self.exit_code(),
        })
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for p in &self.plugins {
            for f in &p.errors {
                let _ = writeln!(out, "ERROR   {} [{}]: {}", p.plugin, f.rule, f.message);
            }
            for f in &p.warnings {
                let _ = writeln!(out, "WARNING {} [{}]: {}", p.plugin, f.rule, f.message);
            }
            for n in &p.notices {
                let _ = writeln!(out, "NOTICE  {}: {n}", p.plugin);
            }
        }
        let width = self
            .plugins
            .iter()
            .map(|p| p.plugin.len())
            .max()
            .unwrap_or(0)
            .max("plugin".len());
        let _ = writeln!(
            out,
            "{:width$}  {:>10}  {:>8}  {:>7}  status",
            "plugin", "operations", "runnable", "derived"
        );
        for p in &self.plugins {
            let _ = writeln!(
                out,
                "{:width$}  {:>10}  {:>8}  {:>7}  {}",
                p.plugin,
                p.operations,
                p.runnable,
                p.derived,
                p.status()
            );
        }
        let _ = writeln!(
            out,
            "plugin-ops-check: {} manifests, {} errors",
            self.plugins.len(),
            self.errors()
        );
        out
    }
}

/// The rule a parser refusal belongs to.
fn rule_of(error: &PackageError) -> &'static str {
    match error {
        PackageError::Operation(e) => match e {
            OperationError::TooMany => "operations-count",
            OperationError::MinCore { .. } => "min-core",
            OperationError::Name(_) => "name",
            OperationError::DuplicateName(_) => "duplicate-name",
            OperationError::Module { .. } => "module",
            OperationError::NotOffered(_) => "flags",
            OperationError::Label { .. } => "label",
            OperationError::Request { .. } => "request",
            OperationError::Param { .. } | OperationError::TooManyParams(_) => "placeholders",
            OperationError::UnknownImport { .. }
            | OperationError::DuplicateImport { .. }
            | OperationError::ForbiddenImport { .. }
            | OperationError::UndeclaredImport { .. }
            | OperationError::TooManyImports(_)
            | OperationError::Interactive { .. } => "imports",
            OperationError::Network { .. } | OperationError::NetworkNeeded { .. } => "network",
            OperationError::KeyUse { .. } | OperationError::TooManyKeyUses(_) => "key-use",
            OperationError::KeyContent { .. } => "key-content",
            OperationError::Profile { .. } => "profile",
        },
        _ => "manifest",
    }
}

/// `plugin.toml` of every `plugins/*` directory, then the extra paths.
fn manifests(root: &Path, extra: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let plugins = root.join("plugins");
    if plugins.is_dir() {
        for entry in
            std::fs::read_dir(&plugins).with_context(|| format!("reading {}", plugins.display()))?
        {
            let path = entry?.path().join("plugin.toml");
            if path.is_file() {
                found.push(path);
            }
        }
        found.sort();
    }
    for path in extra {
        let path = if path.is_dir() {
            path.join("plugin.toml")
        } else {
            path.clone()
        };
        found.push(path);
    }
    Ok(found)
}

/// The module file name of the plugin crate next to `manifest`: the `[lib]` name or the
/// package name, `-` made `_` (as `plugin pack` finds it), else the directory's name.
fn wasm_name(manifest: &Path) -> String {
    let dir = manifest.parent().unwrap_or(Path::new("."));
    let from_cargo = std::fs::read_to_string(dir.join("Cargo.toml"))
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|t| {
            t.get("lib")
                .and_then(|l| l.get("name"))
                .or_else(|| t.get("package").and_then(|p| p.get("name")))
                .and_then(|n| n.as_str().map(str::to_owned))
        });
    let name = from_cargo.unwrap_or_else(|| {
        dir.file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    });
    name.replace('-', "_")
}

/// Lints one manifest file.
pub fn check_one(path: &Path, options: &Options<'_>) -> PluginReport {
    let plugin = path.parent().and_then(Path::file_name).map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let mut report = PluginReport {
        plugin,
        ..PluginReport::default()
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            report.errors.push(Finding {
                rule: "manifest",
                message: format!("reading {}: {e}", path.display()),
            });
            return report;
        }
    };
    let manifest = match Manifest::from_toml(&text) {
        Ok(manifest) => manifest,
        Err(e) => {
            report.errors.push(Finding {
                rule: rule_of(&e),
                message: e.to_string(),
            });
            return report;
        }
    };
    let operations = manifest.operations();
    report.operations = operations.len();
    report.runnable = operations.iter().filter(|o| o.runnable()).count();
    report.derived = operations.iter().filter(|o| o.is_derived()).count();
    if operations.is_empty() {
        return report;
    }
    for op in operations {
        // Defensive: the parser refuses these; a parser regression must not pass silently.
        for key in op.uses().keys() {
            if key.max_uses() != MAX_USES {
                report.errors.push(Finding {
                    rule: "max-uses",
                    message: format!("operation {:?}: max_uses is not {MAX_USES}", op.name()),
                });
            }
            if matches!(key.content(), Content::Derived) && key.kind() == KeyKind::Raw {
                report.errors.push(Finding {
                    rule: "raw-content",
                    message: format!("operation {:?}: raw with derived content", op.name()),
                });
            }
        }
        if op.is_derived() {
            report.notices.push(format!(
                "operation {:?} is blocked until MP3b (derived content is not runnable)",
                op.name()
            ));
        }
    }
    let wasm_path = options.wasm_dir.join(format!("{}.wasm", wasm_name(path)));
    match std::fs::read(&wasm_path) {
        Ok(bytes) => match Engine::new().compile(&manifest, &bytes) {
            Ok(compiled) => {
                let have: Vec<&str> = compiled.imports().iter().map(|i| i.name()).collect();
                for op in operations {
                    for import in op.uses().imports() {
                        if !have.contains(&import.name()) {
                            report.errors.push(Finding {
                                rule: "wasm-imports",
                                message: format!(
                                    "operation {:?} declares import {} the module does not import",
                                    op.name(),
                                    import.name()
                                ),
                            });
                        }
                    }
                }
            }
            Err(e) => report.errors.push(Finding {
                rule: "wasm-imports",
                message: format!("{}: {e}", wasm_path.display()),
            }),
        },
        Err(_) => {
            let message = format!(
                "{} not found: the operations' imports are NOT checked against the module",
                wasm_path.display()
            );
            report.notices.push("wasm imports rule skipped".to_owned());
            let finding = Finding {
                rule: "wasm-missing",
                message,
            };
            if options.require_wasm {
                report.errors.push(finding);
            } else {
                report.warnings.push(finding);
            }
        }
    }
    report
}

/// Lints `plugins/*` of `root` and the extra paths.
///
/// # Errors
///
/// An unreadable `plugins` directory.
pub fn check(root: &Path, options: &Options<'_>) -> anyhow::Result<Report> {
    let plugins = manifests(root, options.extra)?
        .iter()
        .map(|path| check_one(path, options))
        .collect();
    Ok(Report { plugins })
}
