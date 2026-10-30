//! The issues of the watcher, rendered from `diff.json` and the new facts: one `upstream`
//! issue for the core, one `upstream-plugin` issue per changed plugin, `upstream-alert`
//! issues for failures. Each body ends with the marker `<!-- upstream-key: … -->` by which a
//! later run finds it again. Text from the facts is escaped for Markdown.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::diff::{ApiDiff, BundleDiff, FactsDiff, SetDiff};
use super::facts::{BundleFacts, Facts};
use super::poll::AlertKind;
use crate::registry::ports::Port;

const CORE: &str = include_str!("templates/core.md");
const PLUGIN: &str = include_str!("templates/plugin.md");
const ALERT: &str = include_str!("templates/alert.md");

/// Most rows of one table.
pub const ROWS_MAX: usize = 50;
/// Longest body, in characters.
pub const BODY_MAX: usize = 60_000;

/// An issue to create or update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The `upstream-key`.
    pub key: String,
    /// The title.
    pub title: String,
    /// The label.
    pub label: Label,
    /// The body; its last line is the key marker.
    pub body: String,
}

/// The labels of the watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Label {
    /// `upstream`: the core.
    #[serde(rename = "upstream")]
    Upstream,
    /// `upstream-plugin`: a plugin.
    #[serde(rename = "upstream-plugin")]
    UpstreamPlugin,
    /// `upstream-alert`: a failure.
    #[serde(rename = "upstream-alert")]
    UpstreamAlert,
}

impl Label {
    /// Every label.
    pub const ALL: [Label; 3] = [Label::Upstream, Label::UpstreamPlugin, Label::UpstreamAlert];

    /// Its name.
    pub fn name(self) -> &'static str {
        match self {
            Label::Upstream => "upstream",
            Label::UpstreamPlugin => "upstream-plugin",
            Label::UpstreamAlert => "upstream-alert",
        }
    }

    /// Its colour (hex, no `#`).
    pub fn color(self) -> &'static str {
        match self {
            Label::Upstream => "1d76db",
            Label::UpstreamPlugin => "5319e7",
            Label::UpstreamAlert => "b60205",
        }
    }
}

/// A port of a plugin of the original, as the issues name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRef {
    /// `plugins/<short>`.
    pub short: String,
    /// The original's symbolic name.
    pub symname: String,
    /// The original's version the port follows.
    pub version: String,
}

impl From<&Port> for PortRef {
    fn from(p: &Port) -> Self {
        PortRef {
            short: p.short.clone(),
            symname: p.registry.original.symname.clone(),
            version: p.registry.original.version.clone(),
        }
    }
}

/// What a rendering needs beside the facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderCtx {
    /// `owner/name`.
    pub repo: String,
    /// The id of the history entry.
    pub entry_id: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    /// The ports.
    pub ports: Vec<PortRef>,
}

/// The key marker line.
pub fn key_marker(key: &str) -> String {
    format!("<!-- upstream-key: {key} -->")
}

/// The key of a body, from its last line.
pub fn key_of(body: &str) -> Option<String> {
    let last = body.trim_end().lines().last()?.trim();
    let key = last
        .strip_prefix("<!-- upstream-key: ")?
        .strip_suffix(" -->")?;
    (!key.is_empty()).then(|| key.to_owned())
}

fn finish(template: &str, values: &[(&str, String)], key: &str) -> String {
    let mut body = template.to_owned();
    for (name, value) in values {
        body = body.replace(&format!("{{{{{name}}}}}"), value);
    }
    let mut body = body.trim_end().to_owned();
    body.push_str("\n\n");
    body.push_str(&key_marker(key));
    body.push('\n');
    body
}

/// Fact text for prose and table cells: one line, nothing live. `|`, `` ` ``, `<`, `>`, `&`
/// and Markdown punctuation (`\\ [ ] ! * _ ~`) are escaped; a word joiner (U+2060) after `@`
/// and `#` keeps mentions and issue references from linking.
pub fn cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '`' => out.push('\''),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\\' | '[' | ']' | '!' | '*' | '_' | '~' => {
                out.push('\\');
                out.push(c);
            }
            '@' | '#' => {
                out.push(c);
                out.push('\u{2060}');
            }
            '\r' => {}
            '\n' | '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Fact text inside a code span in a table: one line, `|` escaped for the table, `` ` ``
/// replaced; the rest is literal there.
pub fn code(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\r')
        .map(|c| match c {
            '`' => "'".to_owned(),
            '|' => "\\|".to_owned(),
            '\n' | '\t' => " ".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

/// `s` as a block quote, escaped.
pub fn quote(s: &str) -> String {
    s.lines()
        .map(|l| {
            let escaped = cell(l);
            if escaped.trim().is_empty() {
                ">".to_owned()
            } else {
                format!("> {escaped}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn short(hex: &str) -> String {
    cell(&hex[..hex.len().min(16)])
}

/// A table of `rows` under `header`, at most `max` rows.
fn table(header: &str, rows: Vec<String>, max: usize) -> String {
    if rows.is_empty() {
        return "Без изменений.".to_owned();
    }
    let mut out = format!("{header}\n");
    let extra = rows.len().saturating_sub(max);
    for row in rows.into_iter().take(max) {
        out.push_str(&row);
        out.push('\n');
    }
    if extra > 0 {
        let _ = writeln!(out, "\n… и ещё {extra} — полный список в `diff.json`");
    }
    out.trim_end().to_owned()
}

fn set_rows<T: Ord + ToString>(what: &str, d: &SetDiff<T>) -> Vec<String> {
    d.added
        .iter()
        .map(|v| format!("| {what} | добавлено | `{}` |", code(&v.to_string())))
        .chain(
            d.removed
                .iter()
                .map(|v| format!("| {what} | удалено | `{}` |", code(&v.to_string()))),
        )
        .collect()
}

fn api_rows(api: &ApiDiff) -> Vec<String> {
    let mut rows = set_rows("класс", &api.classes);
    for (class, m) in &api.methods {
        rows.extend(set_rows(&format!("метод {}", cell(class)), m));
    }
    for (class, f) in &api.fields {
        rows.extend(set_rows(&format!("поле {}", cell(class)), f));
    }
    rows.extend(set_rows("NCALayerMethod", &api.ncalayer_methods));
    rows.extend(set_rows("имя", &api.names));
    rows.extend(set_rows("код ошибки", &api.error_codes));
    rows.extend(set_rows("URL", &api.urls));
    rows.extend(set_rows("порт", &api.ports));
    rows
}

const API_HEADER: &str = "| Что | Изменение | Значение |\n|---|---|---|";

fn signer_cell(f: Option<&Facts>) -> String {
    f.map_or("—".to_owned(), |f| {
        let s = &f.manifest.signer;
        let cn = s
            .subject
            .split(',')
            .find_map(|p| p.trim().strip_prefix("CN="))
            .unwrap_or("");
        format!("{}, {}, {}", cell(cn), cell(&s.serial), short(&s.sha256))
    })
}

/// The issues of a diff: none for the baseline or only repacks and notes; one for the core
/// when it needs one; one per changed plugin.
pub fn render(diff: &FactsDiff, old: Option<&Facts>, new: &Facts, ctx: &RenderCtx) -> Vec<Issue> {
    let mut issues = Vec::new();
    if diff.baseline {
        return issues;
    }
    let key8 = ctx.entry_id.rsplit('-').next().unwrap_or_default();
    if diff.needs_core_issue() {
        let key = format!("core:{}:{key8}", new.manifest.version);
        let mut body = render_core(diff, old, new, ctx, &key, ROWS_MAX);
        if body.chars().count() > BODY_MAX {
            body = render_core(diff, old, new, ctx, &key, 10);
        }
        issues.push(Issue {
            key,
            title: format!("Оригинал NCALayer: {} ({})", new.manifest.version, ctx.date),
            label: Label::Upstream,
            body,
        });
    }
    for (symname, d) in diff.plugin_issues() {
        let before = old.and_then(|o| o.bundles.get(symname));
        let after = new.bundles.get(symname);
        let key = match d {
            BundleDiff::Removed(_) => format!("plugin:{symname}:removed:{key8}"),
            _ => format!(
                "plugin:{symname}:{}",
                after.map_or("", |b| b.version.as_str())
            ),
        };
        let mut body = render_plugin(symname, d, before, after, ctx, &key, ROWS_MAX);
        if body.chars().count() > BODY_MAX {
            body = render_plugin(symname, d, before, after, ctx, &key, 10);
        }
        let name = after.or(before).map_or(String::new(), |b| b.name.clone());
        issues.push(Issue {
            key,
            title: format!(
                "Плагин оригинала {} ({symname}): {} → {}",
                name,
                before.map_or("—", |b| b.version.as_str()),
                after.map_or("—", |b| b.version.as_str())
            ),
            label: Label::UpstreamPlugin,
            body,
        });
    }
    issues
}

fn render_core(
    diff: &FactsDiff,
    old: Option<&Facts>,
    new: &Facts,
    ctx: &RenderCtx,
    key: &str,
    max: usize,
) -> String {
    let m = &diff.manifest;
    let mut manifest_rows = Vec::new();
    let mut row = |what: &str, before: &str, after: &str| {
        manifest_rows.push(format!("| {what} | {} | {} |", cell(before), cell(after)));
    };
    if let Some(c) = &m.version {
        row("version", &c.before, &c.after);
    }
    if let Some(c) = &m.info {
        row("info", &c.before, &c.after);
    }
    if let Some(c) = &m.updurl {
        row("updurl", &c.before, &c.after);
    }
    for p in &m.syspkgs.added {
        row("syspkgs", "", p);
    }
    for p in &m.syspkgs.removed {
        row("syspkgs", p, "");
    }
    for c in &m.disturls {
        let text = |d: &Option<super::manifest::DistUrl>| {
            d.as_ref().map_or(String::new(), |d| {
                format!("{}: {} {}", d.kind, d.url, &d.hash[..d.hash.len().min(16)])
            })
        };
        row("disturls", &text(&c.before), &text(&c.after));
    }
    for (k, c) in &m.extra {
        row(
            &format!("поле {}", cell(k)),
            c.before.as_deref().unwrap_or(""),
            c.after.as_deref().unwrap_or(""),
        );
    }
    let mut core_rows = Vec::new();
    let mut api = Vec::new();
    for (name, d) in &diff.core {
        let before = old.and_then(|o| o.bundles.get(name));
        let after = new.bundles.get(name);
        let (what, detail) = match d {
            BundleDiff::Added(_) => ("добавлен", String::new()),
            BundleDiff::Removed(_) => ("удалён", String::new()),
            BundleDiff::Changed {
                fields,
                repack_only: true,
                ..
            } => (
                "перепакован",
                fields.keys().cloned().collect::<Vec<_>>().join(", "),
            ),
            BundleDiff::Changed { fields, api: a, .. } => {
                if let Some(a) = a {
                    api.extend(
                        api_rows(a)
                            .into_iter()
                            .map(|r| r.replacen("| ", &format!("| {} · ", cell(name)), 1)),
                    );
                }
                (
                    "изменён",
                    fields.keys().cloned().collect::<Vec<_>>().join(", "),
                )
            }
        };
        core_rows.push(format!(
            "| `{}` | {what} | {} | {} | {} |",
            code(name),
            cell(before.map_or("—", |b| b.version.as_str())),
            cell(after.map_or("—", |b| b.version.as_str())),
            cell(&detail)
        ));
    }
    let mut dist_rows = Vec::new();
    for (id, d) in &diff.distributions {
        if !d.content_changed() {
            continue;
        }
        let sha = d.sha256.as_ref();
        let opt =
            |v: Option<&Option<String>>| v.and_then(|v| v.as_deref()).map_or("—".to_owned(), short);
        dist_rows.push(format!(
            "| `{}` | {} | {} | +{} −{} ~{} |",
            code(id),
            opt(sha.map(|c| &c.before)),
            opt(sha.map(|c| &c.after)),
            d.files.added.len(),
            d.files.removed.len(),
            d.changed_files.len()
        ));
    }
    let signer_warning = if m.signer.is_some() {
        "\n**Сменился сертификат подписи манифеста.** Новый сертификат проверен по корням НУЦ; сверьте его с опубликованным НУЦ.\n".to_owned()
    } else {
        String::new()
    };
    let version_before = old.map_or("—".to_owned(), |o| cell(&o.manifest.version));
    let values = [
        ("version_before", version_before),
        ("version_after", cell(&new.manifest.version)),
        (
            "manifest_before",
            old.map_or("—".to_owned(), |o| short(&o.manifest.sha256)),
        ),
        ("manifest_after", short(&new.manifest.sha256)),
        ("signer_before", signer_cell(old)),
        ("signer_after", signer_cell(Some(new))),
        ("date", cell(&ctx.date)),
        ("signer_warning", signer_warning),
        (
            "manifest",
            table("| Поле | До | После |\n|---|---|---|", manifest_rows, max),
        ),
        (
            "core",
            table(
                "| Бандл | Изменение | До | После | Поля |\n|---|---|---|---|---|",
                core_rows,
                max,
            ),
        ),
        (
            "distributions",
            table(
                "| Источник | sha256 до | sha256 после | Файлы |\n|---|---|---|---|",
                dist_rows,
                max,
            ),
        ),
        ("api", table(API_HEADER, api, max)),
        ("repo", ctx.repo.clone()),
        ("entry_id", ctx.entry_id.clone()),
    ];
    finish(CORE, &values, key)
}

fn render_plugin(
    symname: &str,
    d: &BundleDiff,
    before: Option<&BundleFacts>,
    after: Option<&BundleFacts>,
    ctx: &RenderCtx,
    key: &str,
    max: usize,
) -> String {
    let field =
        |b: Option<&BundleFacts>, f: fn(&BundleFacts) -> String| b.map_or("—".to_owned(), f);
    let rows: Vec<String> = [
        (
            "version",
            (|b: &BundleFacts| cell(&b.version)) as fn(&BundleFacts) -> String,
        ),
        ("url", |b| format!("`{}`", code(&b.url))),
        ("hash", |b| short(&b.hash)),
        ("csernum", |b| cell(&b.csernum)),
        ("chash", |b| short(&b.chash)),
    ]
    .into_iter()
    .map(|(name, f)| format!("| {name} | {} | {} |", field(before, f), field(after, f)))
    .collect();
    let info = after
        .or(before)
        .map(|b| b.info.as_str())
        .filter(|i| !i.is_empty())
        .map_or(String::new(), |i| format!("{}\n", quote(i)));
    let signer_matches = match after.and_then(|b| b.signer_matches) {
        Some(true) => "да",
        Some(false) => "**нет**",
        None => "не проверено",
    };
    let port = ctx.ports.iter().find(|p| p.symname == symname).map_or(
        "Порта нет.".to_owned(),
        |p| {
            format!(
                "Порт: `plugins/{}`, портирована версия {}.",
                code(&p.short),
                cell(&p.version)
            )
        },
    );
    let api = match d {
        BundleDiff::Changed { api: Some(a), .. } => table(API_HEADER, api_rows(a), max),
        BundleDiff::Changed { .. } => "Без изменений или JAR ещё не загружен.".to_owned(),
        BundleDiff::Added(_) => "Новый плагин: API — в `latest/facts.json`.".to_owned(),
        BundleDiff::Removed(_) => "Плагин удалён из манифеста.".to_owned(),
    };
    let values = [
        (
            "name",
            cell(&after.or(before).map_or(String::new(), |b| b.name.clone())),
        ),
        ("symname", code(symname)),
        ("from", cell(before.map_or("—", |b| b.version.as_str()))),
        ("to", cell(after.map_or("—", |b| b.version.as_str()))),
        ("date", cell(&ctx.date)),
        ("fields", rows.join("\n")),
        ("info", info),
        ("signer_matches", signer_matches.to_owned()),
        ("port", port),
        ("api", api),
        ("repo", ctx.repo.clone()),
        ("entry_id", ctx.entry_id.clone()),
    ];
    finish(PLUGIN, &values, key)
}

/// The issue of an alert of `kind` on `date` (one per kind and day).
pub fn render_alert(kind: AlertKind, detail: &str, date: &str, run_url: Option<&str>) -> Issue {
    let what = match kind {
        AlertKind::BadSignature => format!(
            "Подпись манифеста не проверилась: {}. Факты не обновлены.",
            cell(detail)
        ),
        AlertKind::ManifestUnreachable => format!(
            "Манифест недоступен ({}) — возможно, сайты НУЦ недоступны с runner'ов GitHub; см. «Резервный путь» в `docs/dev/upstream-watch.md`.",
            cell(detail)
        ),
        AlertKind::SignerChanged => {
            format!("Сменился сертификат подписи манифеста: {}.", cell(detail))
        }
        AlertKind::CollectFailed => format!("Сбор фактов упал: {}.", cell(detail)),
    };
    // The workflow's own URL; anything else is shown as code.
    let run = run_url.map_or(String::new(), |u| {
        let plain = u.starts_with("https://")
            && u.chars()
                .all(|c| c.is_ascii_alphanumeric() || "/:.-_".contains(c));
        if plain {
            format!("Прогон: {u}\n")
        } else {
            format!("Прогон: `{}`\n", code(u))
        }
    });
    let key = format!("alert:{}:{date}", kind.name());
    let title_what = match kind {
        AlertKind::BadSignature => "подпись манифеста не проверилась",
        AlertKind::ManifestUnreachable => "манифест недоступен",
        AlertKind::SignerChanged => "сменился подписант манифеста",
        AlertKind::CollectFailed => "сбор фактов упал",
    };
    Issue {
        body: finish(
            ALERT,
            &[("what", what), ("date", cell(date)), ("run", run)],
            &key,
        ),
        key,
        title: format!("Наблюдатель за оригиналом: {title_what} ({date})"),
        label: Label::UpstreamAlert,
    }
}

/// The kinds of `issues`' labels (for tests and reports).
pub fn labels(issues: &[Issue]) -> BTreeSet<Label> {
    issues.iter().map(|i| i.label).collect()
}
