//! The sources the watcher polls and their identities. The one-time `download.php?key=`
//! keys of the download page are not part of an identity: a page source is named after the
//! label of its link.

use serde::{Deserialize, Serialize};

use super::Endpoints;
use super::artifact::Format;
use super::http::UrlParts;
use super::manifest::Verified;

/// A source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// Identity: `manifest`, `dist:<type>`, `page:<slug>`, `fixed:<name>`, `bundle:<symname>`.
    pub id: String,
    /// What it is.
    pub kind: SourceKind,
    /// Where it is now (for a page source, with the current key).
    pub url: String,
    /// The SHA-256 the manifest gives.
    pub expected_sha256: Option<String>,
    /// The format it should have.
    pub expected_format: Option<Format>,
}

/// What a source is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// The manifest.
    Manifest,
    /// One of the manifest's `disturls`.
    Dist {
        /// Its `type`.
        kind: String,
    },
    /// A link of the download page.
    Page {
        /// The label of the link.
        label: String,
        /// The SHA-1 published beside it.
        published_sha1: Option<String>,
    },
    /// A file at a fixed address.
    Fixed,
    /// A bundle of the manifest.
    Bundle {
        /// Its symbolic name.
        symname: String,
    },
}

/// A download link of the page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageLink {
    /// The label (text of the link).
    pub label: String,
    /// The label as an identity.
    pub slug: String,
    /// Absolute URL, with the key.
    pub url: String,
    /// The SHA-1 published after the link.
    pub published_sha1: Option<String>,
}

/// How far after a link its SHA-1 may be.
const SHA1_WINDOW: usize = 2048;

/// The download links of the page `html` (address `base`): `<a>` whose path ends with
/// `download.php` with a `key` of 32 hex digits, and the first 40-hex-digit SHA-1 after
/// each (before the next such link, at most 2 KiB on).
pub fn parse_download_page(html: &str, base: &str) -> Vec<PageLink> {
    let Ok(base) = UrlParts::parse(base) else {
        return Vec::new();
    };
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<(usize, usize, String, String)> = Vec::new();
    let mut at = 0;
    while let Some(start) = lower[at..].find("<a").map(|i| i + at) {
        at = start + 2;
        let Some(tag_end) = lower[start..].find('>').map(|i| i + start) else {
            break;
        };
        let tag = &html[start..tag_end];
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        if !is_download_link(&href) {
            continue;
        }
        let close = lower[tag_end..]
            .find("</a")
            .map_or(html.len(), |i| i + tag_end);
        let label = text(&html[tag_end + 1..close]);
        found.push((start, close, label, base.join(&decode_entities(&href))));
    }
    let mut links: Vec<PageLink> = Vec::new();
    for (i, (_, close, label, url)) in found.iter().enumerate() {
        let next = found.get(i + 1).map_or(html.len(), |n| n.0);
        let end = next.min(close + SHA1_WINDOW).min(html.len());
        let window = html.get(*close..end).unwrap_or_default();
        let mut slug = slugify(label);
        let mut n = 2;
        while links.iter().any(|l| l.slug == slug) {
            slug = format!("{}-{n}", slugify(label));
            n += 1;
        }
        links.push(PageLink {
            label: label.clone(),
            slug,
            url: url.clone(),
            published_sha1: first_sha1(window),
        });
    }
    links
}

/// The value of `name` in an HTML tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name).map(|i| i + from) {
        from = i + name.len();
        let before_ok = i == 0 || !lower.as_bytes()[i - 1].is_ascii_alphanumeric();
        let rest = lower[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let value_at = tag.len() - rest.len() + 1;
        let value = tag[value_at..].trim_start();
        return Some(match value.chars().next()? {
            q @ ('"' | '\'') => value[1..].split(q).next()?.to_owned(),
            _ => value
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()?
                .to_owned(),
        });
    }
    None
}

/// Whether `href` is `…download.php?…key=<32 hex>…`.
fn is_download_link(href: &str) -> bool {
    let href = decode_entities(href);
    let Some((path, query)) = href.split_once('?') else {
        return false;
    };
    path.to_ascii_lowercase().ends_with("download.php")
        && query.split('&').any(|p| {
            p.strip_prefix("key=")
                .is_some_and(|k| k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
}

/// The text of an HTML fragment: tags dropped, entities decoded, white space collapsed.
fn text(fragment: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in fragment.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    decode_entities(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first run of exactly 40 hex digits.
fn first_sha1(window: &str) -> Option<String> {
    let bytes = window.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let before = start.checked_sub(1).map(|j| bytes[j]);
            let word = before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'=');
            if i - start == 40 && !word {
                return Some(window[start..i].to_ascii_lowercase());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The identity of a link label: transliterated to lowercase ASCII letters and digits, runs
/// of anything else as one `-`, without leading `ncalayer` and `для` words (unless nothing
/// else is left), e.g. `windows-64-bit`, `korporativnoy-seti`.
pub fn slugify(label: &str) -> String {
    let mut slug = String::new();
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if let Some(latin) = translit(c) {
            slug.push_str(latin);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let mut slug = slug.trim_matches('-');
    for word in ["ncalayer-", "dlya-"] {
        if let Some(rest) = slug.strip_prefix(word)
            && !rest.is_empty()
        {
            slug = rest;
        }
    }
    if slug.is_empty() {
        "link".to_owned()
    } else {
        slug.to_owned()
    }
}

/// Latin letters of a lowercase Cyrillic (Russian and Kazakh) letter.
fn translit(c: char) -> Option<&'static str> {
    Some(match c {
        'а' | 'ә' => "a",
        'б' => "b",
        'в' => "v",
        'г' | 'ғ' => "g",
        'д' => "d",
        'е' | 'ё' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' | 'і' => "i",
        'й' => "y",
        'к' | 'қ' => "k",
        'л' => "l",
        'м' => "m",
        'н' | 'ң' => "n",
        'о' | 'ө' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' | 'ұ' | 'ү' => "u",
        'ф' => "f",
        'х' | 'һ' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "",
        'ы' => "y",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        _ => return None,
    })
}

/// The format of a file named `name` (or a link labelled so), by extension or label words.
pub fn format_for_name(name: &str) -> Option<Format> {
    let lower = name.to_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e);
    match ext {
        Some("exe") => return Some(Format::InnoExe),
        Some("msi") => return Some(Format::Msi),
        Some("dmg") => return Some(Format::Dmg),
        Some("zip") => return Some(Format::Zip),
        Some("sh") => return Some(Format::Sh),
        Some("jar") => return Some(Format::Jar),
        _ => {}
    }
    if lower.contains("корпоратив") || lower.contains("msi") {
        Some(Format::Msi)
    } else if lower.contains("windows") {
        Some(Format::InnoExe)
    } else if lower.contains("mac") {
        Some(Format::Dmg)
    } else if lower.contains("linux") {
        Some(Format::Zip)
    } else {
        None
    }
}

/// The format a `disturls` type gives.
pub fn dist_format(kind: &str) -> Option<Format> {
    match kind {
        "setupexe" => Some(Format::GoDropper),
        "setupsh" => Some(Format::Sh),
        "appzip" => Some(Format::Zip),
        "jar" => Some(Format::Jar),
        _ => None,
    }
}

/// The sources of a verified manifest, the page's links and the fixed files, sorted by id.
pub fn discover(verified: &Verified, page: &[PageLink], endpoints: &Endpoints) -> Vec<Source> {
    let nonempty = |s: &str| (!s.is_empty()).then(|| s.to_ascii_lowercase());
    let mut sources = vec![Source {
        id: "manifest".to_owned(),
        kind: SourceKind::Manifest,
        url: endpoints.manifest.clone(),
        expected_sha256: None,
        expected_format: Some(Format::Der),
    }];
    for d in &verified.manifest.disturls {
        if d.url.is_empty() {
            continue;
        }
        sources.push(Source {
            id: format!("dist:{}", d.kind),
            kind: SourceKind::Dist {
                kind: d.kind.clone(),
            },
            url: d.url.clone(),
            expected_sha256: nonempty(&d.hash),
            expected_format: dist_format(&d.kind),
        });
    }
    for link in page {
        sources.push(Source {
            id: format!("page:{}", link.slug),
            kind: SourceKind::Page {
                label: link.label.clone(),
                published_sha1: link.published_sha1.clone(),
            },
            url: link.url.clone(),
            expected_sha256: None,
            expected_format: format_for_name(&link.label),
        });
    }
    for (id, url) in &endpoints.fixed {
        sources.push(Source {
            id: id.clone(),
            kind: SourceKind::Fixed,
            url: url.clone(),
            expected_sha256: None,
            expected_format: id
                .strip_prefix("fixed:")
                .and_then(|name| format_for_name(name).filter(|f| *f != Format::InnoExe)),
        });
    }
    for b in &verified.manifest.bundles {
        if b.symname.is_empty() {
            continue;
        }
        sources.push(Source {
            id: format!("bundle:{}", b.symname),
            kind: SourceKind::Bundle {
                symname: b.symname.clone(),
            },
            url: b.url.clone(),
            expected_sha256: nonempty(&b.hash),
            expected_format: Some(Format::Jar),
        });
    }
    sources.sort_by(|a, b| a.id.cmp(&b.id));
    sources.dedup_by(|a, b| a.id == b.id);
    sources
}

/// A URL without its query (the page's one-time key).
pub fn without_query(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_owned()
}
