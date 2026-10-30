//! The site's hand-written sources, `site/`: the configuration the other parts read, and the
//! rules the sources keep (checked by tests, before Zola sees them).

use std::path::Path;

use anyhow::{Context, bail};

use super::SITE_DIR;
use crate::plugin::read_limited;

/// What the build and the check read from `site/config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteConfig {
    /// The site's address, without a trailing `/`.
    pub base_url: String,
    /// The language of the pages at the root.
    pub default_language: String,
    /// The other languages, each under `/<lang>/`.
    pub languages: Vec<String>,
}

/// `site/config.toml` of `root`.
///
/// # Errors
///
/// The file cannot be read or lacks `base_url` or `default_language`.
pub fn site_config(root: &Path) -> anyhow::Result<SiteConfig> {
    let path = root.join(SITE_DIR).join("config.toml");
    let text = String::from_utf8(read_limited(&path, 1024 * 1024)?)
        .with_context(|| path.display().to_string())?;
    let table: toml::Table = toml::from_str(&text).with_context(|| path.display().to_string())?;
    let string = |key: &str| -> anyhow::Result<String> {
        match table.get(key).and_then(toml::Value::as_str) {
            Some(value) => Ok(value.to_owned()),
            None => bail!("{}: no {key}", path.display()),
        }
    };
    let languages = table
        .get("languages")
        .and_then(toml::Value::as_table)
        .map(|languages| languages.keys().cloned().collect())
        .unwrap_or_default();
    Ok(SiteConfig {
        base_url: string("base_url")?.trim_end_matches('/').to_owned(),
        default_language: string("default_language")?,
        languages,
    })
}

/// The project's GitHub Pages address, `https://<owner>.github.io/<repo>`, from the
/// repository's.
pub fn pages_url() -> String {
    let repository = env!("CARGO_PKG_REPOSITORY");
    let path = repository
        .strip_prefix("https://github.com/")
        .unwrap_or(repository);
    let (owner, repo) = path.split_once('/').unwrap_or((path, ""));
    format!("https://{owner}.github.io/{repo}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn site() -> PathBuf {
        oncl_testkit::workspace_root().join(SITE_DIR)
    }

    fn config() -> toml::Table {
        toml::from_str(&fs::read_to_string(site().join("config.toml")).unwrap()).unwrap()
    }

    /// Every file under `dir`, recursively.
    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    fn templates() -> Vec<(PathBuf, String)> {
        files(&site().join("templates"))
            .into_iter()
            .map(|p| {
                let text = fs::read_to_string(&p).unwrap();
                (p, text)
            })
            .collect()
    }

    /// The translation tables: the default language's, then each other language's.
    fn translations() -> Vec<(String, toml::Table)> {
        let config = config();
        let mut out = vec![(
            "ru".to_owned(),
            config["translations"].as_table().unwrap().clone(),
        )];
        for (lang, table) in config["languages"].as_table().unwrap() {
            out.push((
                lang.clone(),
                table["translations"].as_table().unwrap().clone(),
            ));
        }
        out
    }

    #[test]
    fn config_is_the_project_site() {
        let config = site_config(&oncl_testkit::workspace_root()).unwrap();
        assert_eq!(config.base_url, pages_url());
        assert_eq!(config.base_url, "https://arynyklas.github.io/open-ncalayer");
        assert_eq!(config.default_language, "ru");
        assert_eq!(config.languages, ["en", "kk"]);
    }

    #[test]
    fn translations_complete() {
        let tables = translations();
        assert_eq!(tables.len(), 3);
        let keys: BTreeSet<&String> = tables[0].1.keys().collect();
        for (lang, table) in &tables {
            assert_eq!(table.keys().collect::<BTreeSet<_>>(), keys, "{lang}");
            for (key, value) in table {
                let text = value.as_str().unwrap_or_default();
                assert!(!text.trim().is_empty(), "{lang}.{key}");
            }
        }
    }

    /// The keys templates build from data: every value the data may hold.
    fn dynamic_keys() -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for status in ["full", "partial", "needs_tokens"] {
            keys.push(format!("status_{status}"));
        }
        for conformance in ["computed", "confirmed"] {
            keys.push(format!("conformance_{conformance}"));
        }
        for state in ["same", "changed", "removed", "unknown"] {
            keys.push(format!("original_{state}"));
        }
        for kind in ["baseline", "change", "repack"] {
            keys.push(format!("kind_{kind}"));
        }
        for change in ["added", "removed", "changed"] {
            keys.push(format!("change_{change}"));
        }
        for which in ["release", "prerelease"] {
            keys.push(format!("download_{which}"));
            keys.push(format!("download_no_{which}"));
        }
        for asset in [
            "win-x64",
            "win-x86",
            "win7-x64",
            "win7-x86",
            "osx-pkg",
            "osx-zip",
            "linux-appimage",
            "chromium",
            "firefox",
            "sha256sums",
        ] {
            keys.push(format!("asset_{}", asset.replace('-', "_")));
        }
        keys
    }

    #[test]
    fn dynamic_translation_keys_exist() {
        let table = &translations()[0].1;
        for key in dynamic_keys() {
            assert!(table.contains_key(&key), "{key}");
        }
    }

    #[test]
    fn every_translation_key_is_used() {
        let dynamic = dynamic_keys();
        let templates: Vec<String> = templates().into_iter().map(|(_, text)| text).collect();
        for key in translations()[0].1.keys() {
            let used = dynamic.contains(key)
                || templates.iter().any(|text| {
                    text.contains(&format!("\"{key}\"")) || text.contains(&format!("'{key}'"))
                });
            assert!(used, "{key} is not used by any template");
        }
    }

    #[test]
    fn templates_use_only_known_translation_keys() {
        let table = &translations()[0].1;
        let mut used = 0;
        for (path, text) in templates() {
            for quote in ['"', '\''] {
                let marker = format!("trans(key={quote}");
                for (at, _) in text.match_indices(&marker) {
                    let rest = &text[at + marker.len()..];
                    let end = rest.find(quote).unwrap();
                    let key = &rest[..end];
                    if rest[end + 1..].trim_start().starts_with('~') {
                        // A prefix of keys made from data: `dynamic_translation_keys_exist`.
                        continue;
                    }
                    assert!(table.contains_key(key), "{}: {key}", path.display());
                    used += 1;
                }
            }
        }
        assert!(used > 50, "{used}");
    }

    #[test]
    fn templates_have_no_safe_filter() {
        for (path, text) in templates() {
            let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(!compact.contains("|safe"), "{}", path.display());
            assert!(!text.contains("safe("), "{}", path.display());
        }
    }

    #[test]
    fn templates_have_no_script_or_external_assets() {
        for (path, text) in templates() {
            let lower = text.to_ascii_lowercase();
            for forbidden in ["<script", "<iframe", "<object", "<embed", "http://"] {
                assert!(
                    !lower.contains(forbidden),
                    "{}: {forbidden}",
                    path.display()
                );
            }
            for attr in ["src=\"https://", "src='https://"] {
                assert!(!lower.contains(attr), "{}: {attr}", path.display());
            }
            for line in lower.lines().filter(|l| l.contains("<link")) {
                assert!(!line.contains("https://"), "{}: {line}", path.display());
            }
        }
    }

    #[test]
    fn content_has_three_languages() {
        let content = site().join("content");
        let mut indexes = 0;
        for path in files(&content) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name == "_index.md" {
                indexes += 1;
                for lang in ["kk", "en"] {
                    let other = path.with_file_name(format!("_index.{lang}.md"));
                    assert!(other.is_file(), "{}", other.display());
                }
            }
        }
        assert_eq!(indexes, 4);
    }

    #[test]
    fn site_has_no_updates_path() {
        let site = site();
        assert!(!site.join("content/updates").exists());
        assert!(!site.join("static/updates").exists());
        assert!(!site.join("data").exists());
        for path in files(&site) {
            let rel = path
                .strip_prefix(&site)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            assert!(!rel.split('/').any(|part| part == "updates"), "{rel}");
        }
    }

    #[test]
    fn pages_url_of_the_repository() {
        assert_eq!(pages_url(), "https://arynyklas.github.io/open-ncalayer");
    }
}
