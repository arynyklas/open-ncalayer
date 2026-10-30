//! The offline check of the built site: every internal link and fragment resolves, external
//! links go only where the project allows, no page loads anything from elsewhere or runs
//! scripts, and every page keeps the policy and the accessibility minimum the templates
//! promise. All violations are listed together.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};

/// The policy every page declares.
pub const CSP: &str =
    "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'";

/// The pages every build has.
pub const REQUIRED: [&str; 13] = [
    "index.html",
    "plugins/index.html",
    "download/index.html",
    "upstream/index.html",
    "kk/index.html",
    "kk/plugins/index.html",
    "kk/download/index.html",
    "kk/upstream/index.html",
    "en/index.html",
    "en/plugins/index.html",
    "en/download/index.html",
    "en/upstream/index.html",
    "404.html",
];

/// The external places a page may link to (`<a href>` only), as prefixes: the project's
/// repository (releases, the `upstream` branch, issues, the README) and its AUR package.
/// Another one needs a reason here.
pub const EXTERNAL_ALLOWED: [&str; 2] = [
    "https://github.com/arynyklas/open-ncalayer/",
    "https://aur.archlinux.org/packages/openncalayer-bin",
];

/// The catalog pages: each row of the ports' table carries the bundle's symbolic name.
const CATALOGS: [&str; 3] = [
    "plugins/index.html",
    "kk/plugins/index.html",
    "en/plugins/index.html",
];

/// What a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The HTML pages checked.
    pub pages: usize,
    /// The links followed.
    pub links: usize,
}

/// A URL attribute of a tag, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    /// The tag, lowercase.
    pub tag: String,
    /// The attribute, lowercase.
    pub attr: String,
    /// The value, entities decoded.
    pub value: String,
}

/// A start or end tag.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tag {
    /// The name, lowercase; `/name` for an end tag.
    name: String,
    /// The attributes, names lowercase, values decoded.
    attrs: Vec<(String, String)>,
}

impl Tag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The tags of `html`, comments skipped.
fn tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if html[i..].starts_with("<!--") {
            i = html[i + 4..]
                .find("-->")
                .map_or(b.len(), |end| i + 4 + end + 3);
            continue;
        }
        let start = i + 1;
        let closing = b.get(start) == Some(&b'/');
        let name_start = if closing { start + 1 } else { start };
        if !b.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            i += 1;
            continue;
        }
        let mut j = name_start;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-') {
            j += 1;
        }
        let mut name = html[name_start..j].to_ascii_lowercase();
        if closing {
            name.insert(0, '/');
        }
        let mut attrs = Vec::new();
        loop {
            while j < b.len() && (b[j].is_ascii_whitespace() || b[j] == b'/') {
                j += 1;
            }
            if j >= b.len() || b[j] == b'>' {
                j += 1;
                break;
            }
            let attr_start = j;
            while j < b.len() && !b[j].is_ascii_whitespace() && !matches!(b[j], b'=' | b'>' | b'/')
            {
                j += 1;
            }
            let attr = html[attr_start..j].to_ascii_lowercase();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut value = String::new();
            if b.get(j) == Some(&b'=') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                match b.get(j) {
                    Some(&q @ (b'"' | b'\'')) => {
                        let end = html[j + 1..].find(q as char).map_or(b.len(), |e| j + 1 + e);
                        value = decode(&html[j + 1..end]);
                        j = end + 1;
                    }
                    _ => {
                        let s = j;
                        while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                            j += 1;
                        }
                        value = decode(&html[s..j]);
                    }
                }
            }
            if attr.is_empty() {
                j += 1;
                continue;
            }
            attrs.push((attr, value));
        }
        out.push(Tag { name, attrs });
        i = j;
    }
    out
}

/// The URL attributes (`href`, `src`) of `html`.
pub(crate) fn links(html: &str) -> Vec<Link> {
    tags(html)
        .iter()
        .flat_map(|tag| {
            tag.attrs
                .iter()
                .filter(|(attr, _)| attr == "href" || attr == "src")
                .map(|(attr, value)| Link {
                    tag: tag.name.clone(),
                    attr: attr.clone(),
                    value: value.clone(),
                })
        })
        .collect()
}

/// `text` with character references decoded.
fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|&end| end <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .map(|hex| u32::from_str_radix(hex, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Checks the built site `public` whose address is `base_url`.
///
/// # Errors
///
/// Every violation, a line each (`<file>: <violation>`), or an unreadable directory.
pub fn check(public: &Path, base_url: &str) -> anyhow::Result<Report> {
    let base_url = base_url.trim_end_matches('/');
    let base_path = base_url
        .strip_prefix("https://")
        .and_then(|rest| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("");
    let mut files = BTreeSet::new();
    walk(public, Path::new(""), &mut files)?;
    let mut titled = BTreeSet::new();
    let pages: BTreeMap<&String, (Vec<Tag>, String)> = files
        .iter()
        .filter(|f| f.ends_with(".html"))
        .map(|f| {
            let html = fs::read_to_string(public.join(f)).with_context(|| f.clone())?;
            if has_title(&html) {
                titled.insert(f);
            }
            Ok((f, (tags(&html), html)))
        })
        .collect::<anyhow::Result<_>>()?;
    let ids: BTreeMap<&String, BTreeSet<&str>> = pages
        .iter()
        .map(|(f, (tags, _))| (*f, tags.iter().filter_map(|t| t.attr("id")).collect()))
        .collect();

    let mut errors = Vec::new();
    for required in REQUIRED {
        if !files.contains(required) {
            errors.push(format!("{required}: missing"));
        }
    }
    let mut followed = 0;
    for (file, (tags, html)) in &pages {
        let mut problem = |what: String| errors.push(format!("{file}: {what}"));
        if !titled.contains(file) {
            problem("<title> is missing or empty".to_owned());
        }
        page_rules(file, tags, &mut problem);
        for link in links(html) {
            followed += 1;
            if let Err(what) = check_link(file, &link, base_url, base_path, &files, &ids) {
                problem(what);
            }
        }
    }
    if !errors.is_empty() {
        bail!(
            "{} problems in {}:\n{}",
            errors.len(),
            public.display(),
            errors.join("\n")
        );
    }
    Ok(Report {
        pages: pages.len(),
        links: followed,
    })
}

/// Whether the page's `<title>` has text.
fn has_title(html: &str) -> bool {
    html.find("<title>")
        .map(|at| &html[at + "<title>".len()..])
        .and_then(|rest| rest.find("</title>").map(|end| &rest[..end]))
        .is_some_and(|text| !text.trim().is_empty())
}

fn walk(dir: &Path, rel: &Path, out: &mut BTreeSet<String>) -> anyhow::Result<()> {
    let path = dir.join(rel);
    for entry in fs::read_dir(&path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        let rel = rel.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            walk(dir, &rel, out)?;
        } else {
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

/// The rules of one page that are not about links.
fn page_rules(file: &str, tags: &[Tag], problem: &mut impl FnMut(String)) {
    let count = |name: &str| tags.iter().filter(|t| t.name == name).count();
    for forbidden in ["script", "iframe", "object", "embed"] {
        if count(forbidden) > 0 {
            problem(format!("<{forbidden}> is not allowed"));
        }
    }
    for tag in tags {
        for (attr, _) in &tag.attrs {
            if attr.starts_with("on") {
                problem(format!("the event handler {attr}= on <{}>", tag.name));
            }
        }
    }
    let lang = tags
        .iter()
        .find(|t| t.name == "html")
        .and_then(|t| t.attr("lang"));
    if !matches!(lang, Some("ru" | "kk" | "en")) {
        problem(format!("<html lang> is {lang:?}, not ru, kk or en"));
    }
    for name in ["h1", "main"] {
        let n = count(name);
        if n != 1 {
            problem(format!("{n} <{name}>, not one"));
        }
    }
    let csp: Vec<&str> = tags
        .iter()
        .filter(|t| {
            t.name == "meta"
                && t.attr("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("content-security-policy"))
        })
        .map(|t| t.attr("content").unwrap_or(""))
        .collect();
    if csp.len() != 1 || csp[0] != CSP {
        problem(format!(
            "the Content-Security-Policy meta is {csp:?}, not [{CSP:?}]"
        ));
    }
    let after_body = tags.iter().skip_while(|t| t.name != "body").nth(1);
    if !after_body.is_some_and(|t| t.name == "a" && t.attr("href") == Some("#content")) {
        problem("the first element of <body> is not the skip link to #content".to_owned());
    }
    if CATALOGS.contains(&file) {
        let mut in_ports = false;
        let mut in_body = false;
        let mut found = false;
        for tag in tags {
            match tag.name.as_str() {
                "table"
                    if tag
                        .attr("class")
                        .is_some_and(|c| c.split(' ').any(|c| c == "ports")) =>
                {
                    in_ports = true;
                    found = true;
                }
                "/table" => in_ports = false,
                "tbody" => in_body = in_ports,
                "/tbody" => in_body = false,
                "tr" if in_body && tag.attr("id").is_none_or(str::is_empty) => {
                    problem("a row of the ports' table has no id".to_owned());
                }
                _ => {}
            }
        }
        if !found {
            problem("no ports' table".to_owned());
        }
    }
}

fn check_link(
    file: &str,
    link: &Link,
    base_url: &str,
    base_path: &str,
    files: &BTreeSet<String>,
    ids: &BTreeMap<&String, BTreeSet<&str>>,
) -> Result<(), String> {
    let value = link.value.as_str();
    let what = format!("<{} {}={value:?}>", link.tag, link.attr);
    let lower = value.to_ascii_lowercase();
    if let Some(fragment) = value.strip_prefix('#') {
        return fragment_in(file, fragment, ids).map_err(|e| format!("{what}: {e}"));
    }
    let internal = if let Some(rest) = value.strip_prefix(base_url) {
        if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('#')) {
            return Err(format!("{what}: not under the site"));
        }
        Some(rest.trim_start_matches('/').to_owned())
    } else if lower.starts_with("https://") {
        if link.tag != "a" || link.attr != "href" {
            return Err(format!("{what}: external resources are not allowed"));
        }
        if !EXTERNAL_ALLOWED.iter().any(|p| value.starts_with(p)) {
            return Err(format!("{what}: external link outside the allowed places"));
        }
        None
    } else if lower.starts_with("//")
        || value.contains(':') && !value.starts_with('/') && {
            let colon = value.find(':').unwrap_or(0);
            !value[..colon].contains('/')
        }
    {
        return Err(format!("{what}: scheme not allowed"));
    } else if let Some(rest) = value
        .strip_prefix(&format!("{base_path}/"))
        .filter(|_| !base_path.is_empty())
    {
        Some(rest.to_owned())
    } else if value.starts_with('/') {
        return Err(format!("{what}: not under the site"));
    } else {
        let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
        Some(if dir.is_empty() {
            value.to_owned()
        } else {
            format!("{dir}/{value}")
        })
    };
    let Some(target) = internal else {
        return Ok(());
    };
    let (path, fragment) = match target.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (target.as_str(), None),
    };
    if path.contains('?') {
        return Err(format!("{what}: query not allowed"));
    }
    let resolved = resolve(path).ok_or_else(|| format!("{what}: leaves the site"))?;
    if !files.contains(&resolved) {
        return Err(format!("{what}: {resolved} does not exist"));
    }
    if let Some(fragment) = fragment
        && !fragment.is_empty()
    {
        fragment_in(&resolved, fragment, ids).map_err(|e| format!("{what}: {e}"))?;
    }
    Ok(())
}

/// The file `path` (relative to the site, may end in `/` or name a directory) means.
fn resolve(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    let last_is_file = !path.ends_with('/') && parts.last().is_some_and(|p| p.contains('.'));
    if !last_is_file {
        parts.push("index.html");
    }
    Some(parts.join("/"))
}

fn fragment_in(
    file: &str,
    fragment: &str,
    ids: &BTreeMap<&String, BTreeSet<&str>>,
) -> Result<(), String> {
    let found = ids
        .iter()
        .find(|(f, _)| f.as_str() == file)
        .is_some_and(|(_, ids)| ids.contains(fragment));
    if found {
        Ok(())
    } else {
        Err(format!("no id {fragment:?} in {file}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://arynyklas.github.io/open-ncalayer";

    fn page(lang: &str, body: &str) -> String {
        format!(
            "<!DOCTYPE html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\n\
             <title>T</title>\n<link rel=\"stylesheet\" href=\"{BASE}/style.css\">\n</head>\n\
             <body>\n<a class=\"skip\" href=\"#content\">skip</a>\n<main id=\"content\">\n\
             <h1>T</h1>\n{body}\n</main>\n</body>\n</html>\n"
        )
    }

    const CATALOG: &str = "<table class=\"ports\"><thead><tr><th scope=\"col\">x</th></tr></thead>\
                           <tbody><tr id=\"kz.a\"><td>a</td></tr></tbody></table>";

    /// A minimal site that passes; `extra` replaces or adds pages.
    fn site(extra: &[(&str, String)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut pages: BTreeMap<String, String> = BTreeMap::new();
        for required in REQUIRED {
            let lang = match required.split('/').next() {
                Some("kk") => "kk",
                Some("en") => "en",
                _ => "ru",
            };
            let body = if CATALOGS.contains(&required) {
                CATALOG
            } else {
                ""
            };
            pages.insert(required.to_owned(), page(lang, body));
        }
        pages.insert("style.css".to_owned(), String::new());
        for (name, content) in extra {
            pages.insert((*name).to_owned(), content.clone());
        }
        for (name, content) in pages {
            let path = dir.path().join(&name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        dir
    }

    fn problems(dir: &tempfile::TempDir) -> String {
        format!("{:#}", check(dir.path(), BASE).unwrap_err())
    }

    #[test]
    fn minimal_site_passes() {
        let dir = site(&[]);
        let report = check(dir.path(), BASE).unwrap();
        assert_eq!(report.pages, 13);
        assert_eq!(report.links, 26);
    }

    #[test]
    fn relative_and_absolute_links_resolve() {
        let body = format!(
            "<a href=\"{BASE}/plugins/\">a</a><a href=\"/open-ncalayer/plugins/#kz.a\">b</a>\
             <a href=\"plugins/\">c</a><a href=\"../index.html\">d</a><a href=\"kk/plugins\">e</a>\
             <a href=\"{BASE}\">f</a><a href=\"{BASE}/plugins/#kz.a\">g</a><a href=\"#content\">h</a>"
        );
        let dir = site(&[("index.html", page("ru", &body))]);
        let errors = format!("{:#}", check(dir.path(), BASE).unwrap_err());
        // `../index.html` from the root leaves the site.
        assert!(errors.contains("leaves the site"), "{errors}");
        assert_eq!(errors.lines().count(), 2, "{errors}");
        let body = body.replace("<a href=\"../index.html\">d</a>", "");
        let dir = site(&[("index.html", page("ru", &body))]);
        check(dir.path(), BASE).unwrap();
    }

    #[test]
    fn missing_page_is_reported() {
        let dir = site(&[("index.html", page("ru", "<a href=\"nowhere/\">x</a>"))]);
        assert!(problems(&dir).contains("nowhere/index.html does not exist"));
    }

    #[test]
    fn missing_fragment_is_reported() {
        let body = format!("<a href=\"{BASE}/plugins/#kz.b\">x</a><a href=\"#nope\">y</a>");
        let dir = site(&[("index.html", page("ru", &body))]);
        let errors = problems(&dir);
        assert!(
            errors.contains("no id \"kz.b\" in plugins/index.html"),
            "{errors}"
        );
        assert!(errors.contains("no id \"nope\" in index.html"), "{errors}");
    }

    #[test]
    fn entities_in_href_are_decoded() {
        let body = "<a href=\"https:&#x2F;&#x2F;arynyklas.github.io&#x2F;open-ncalayer&#x2F;plugins&#x2F;\">x</a>";
        let dir = site(&[("index.html", page("ru", body))]);
        check(dir.path(), BASE).unwrap();
        assert_eq!(
            links("<a href='a&amp;b&#39;&lt;&#x41;'>")[0].value,
            "a&b'<A"
        );
    }

    #[test]
    fn script_and_event_handlers_are_rejected() {
        let body = "<script>1</script><img src=\"style.css\" onerror=\"x\"><IFRAME></IFRAME>";
        let dir = site(&[("index.html", page("ru", body))]);
        let errors = problems(&dir);
        assert!(errors.contains("<script>"), "{errors}");
        assert!(errors.contains("onerror="), "{errors}");
        assert!(errors.contains("<iframe>"), "{errors}");
    }

    #[test]
    fn third_party_stylesheet_is_rejected() {
        let html = page("ru", "").replace(
            "</head>",
            "<link rel=\"stylesheet\" href=\"https://github.com/arynyklas/open-ncalayer/x.css\"></head>",
        );
        let dir = site(&[("index.html", html)]);
        assert!(problems(&dir).contains("external resources are not allowed"));
        let dir = site(&[(
            "index.html",
            page(
                "ru",
                "<img src=\"https://aur.archlinux.org/packages/openncalayer-bin\">",
            ),
        )]);
        assert!(problems(&dir).contains("external resources are not allowed"));
    }

    #[test]
    fn external_link_outside_allowlist_is_rejected() {
        let body = "<a href=\"https://github.com/arynyklas/open-ncalayer/releases\">ok</a>\
                    <a href=\"https://aur.archlinux.org/packages/openncalayer-bin\">ok</a>\
                    <a href=\"https://github.com/arynyklas/open-ncalayer-other/\">no</a>\
                    <a href=\"https://example.com/\">no</a>";
        let dir = site(&[("index.html", page("ru", body))]);
        let errors = problems(&dir);
        assert_eq!(errors.matches("outside the allowed").count(), 2, "{errors}");
    }

    #[test]
    fn insecure_and_javascript_urls_are_rejected() {
        let body = "<a href=\"http://github.com/arynyklas/open-ncalayer/\">a</a>\
                    <a href=\"javascript:alert(1)\">b</a><a href=\"data:text/html,x\">c</a>\
                    <a href=\"//example.com/\">d</a><a href=\"mailto:x@example.com\">e</a>\
                    <a href=\"JavaScript:x\">f</a>";
        let dir = site(&[("index.html", page("ru", body))]);
        let errors = problems(&dir);
        assert_eq!(errors.matches("scheme not allowed").count(), 6, "{errors}");
    }

    #[test]
    fn page_without_lang_title_or_h1_is_reported() {
        let html = page("de", "<h1>second</h1>").replace("<main id=\"content\">", "<main><main>");
        let dir = site(&[("index.html", html)]);
        let errors = problems(&dir);
        assert!(errors.contains("<html lang>"), "{errors}");
        assert!(errors.contains("2 <h1>"), "{errors}");
        assert!(errors.contains("2 <main>"), "{errors}");
        let html = page("ru", "").replace("<title>T</title>", "<title> </title>");
        let dir = site(&[("index.html", html)]);
        assert!(problems(&dir).contains("<title>"));
    }

    #[test]
    fn missing_csp_is_reported() {
        let html = page("ru", "").replace("form-action 'none'", "");
        let dir = site(&[("index.html", html)]);
        assert!(problems(&dir).contains("Content-Security-Policy"));
        let html = page("ru", "").replace("<a class=\"skip\" href=\"#content\">skip</a>", "");
        let dir = site(&[("index.html", html)]);
        assert!(problems(&dir).contains("skip link"));
    }

    #[test]
    fn required_pages_are_checked() {
        let dir = site(&[]);
        fs::remove_file(dir.path().join("kk/upstream/index.html")).unwrap();
        fs::remove_file(dir.path().join("404.html")).unwrap();
        let errors = problems(&dir);
        assert!(
            errors.contains("kk/upstream/index.html: missing"),
            "{errors}"
        );
        assert!(errors.contains("404.html: missing"), "{errors}");
    }

    #[test]
    fn catalog_rows_need_ids() {
        let body = CATALOG.replace("<tr id=\"kz.a\">", "<tr>");
        let dir = site(&[("en/plugins/index.html", page("en", &body))]);
        let errors = problems(&dir);
        assert!(errors.contains("en/plugins/index.html: a row"), "{errors}");
        let dir = site(&[("kk/plugins/index.html", page("kk", ""))]);
        assert!(problems(&dir).contains("no ports' table"));
    }

    #[test]
    fn comments_are_not_links() {
        let body = "<!-- <a href=\"https://example.com/\">x</a> <script> -->";
        let dir = site(&[("index.html", page("ru", body))]);
        check(dir.path(), BASE).unwrap();
    }

    #[test]
    fn escaped_text_is_not_markup() {
        let body =
            "&lt;script&gt;alert(1)&lt;/script&gt; &quot;&gt;&lt;img src=x onerror=alert(1)&gt;";
        let dir = site(&[("index.html", page("ru", body))]);
        check(dir.path(), BASE).unwrap();
    }

    #[test]
    fn all_violations_listed_together() {
        let dir = site(&[
            (
                "index.html",
                page("ru", "<a href=\"x/\">x</a><script></script>"),
            ),
            ("en/index.html", page("xx", "")),
        ]);
        let errors = problems(&dir);
        assert!(errors.starts_with("3 problems"), "{errors}");
        assert!(errors.contains("\nindex.html: "), "{errors}");
        assert!(errors.contains("\nen/index.html: "), "{errors}");
    }
}
