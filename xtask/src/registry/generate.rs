//! The site's build copy: `site/` copied as it is, plus what is generated — a stub page of
//! each port in each language and `data/site.json`. Nothing generated is kept in `site/`.

use std::fs;
use std::path::Path;

use anyhow::{Context, bail};

use super::data::site_data;
use super::inputs::{read_channels, read_releases, read_upstream};
use super::ports::load;
use super::{Inputs, LANGS, SITE_DIR};

/// The index pages of `content/plugins`, the only files `site/` keeps there.
const PLUGIN_INDEXES: [&str; 3] = ["_index.md", "_index.kk.md", "_index.en.md"];

/// The stub page of the port `short`: the template and the short name, no data.
pub fn stub(short: &str) -> String {
    format!("+++\ntemplate = \"plugin.html\"\n[extra]\nshort = \"{short}\"\n+++\n")
}

/// Writes the build copy `src`: `root/site` and the generated files.
///
/// # Errors
///
/// `site/` holds generated files or a symbolic link, a port, `registry.toml` or index is
/// invalid, or I/O fails. A missing or broken external input (releases, `upstream`) is a
/// warning instead, returned.
pub fn generate(root: &Path, inputs: &Inputs, src: &Path) -> anyhow::Result<Vec<String>> {
    let site = root.join(SITE_DIR);
    check_site(&site)?;
    let ports = load(&inputs.plugins)?;
    let channels = match &inputs.updates {
        Some(dir) => read_channels(dir)?,
        None => Default::default(),
    };
    let mut warnings = Vec::new();
    let releases = inputs
        .releases
        .as_ref()
        .and_then(|path| match read_releases(path) {
            Ok(releases) => Some(releases),
            Err(e) => {
                warnings.push(format!("releases are left out: {e:#}"));
                None
            }
        });
    let upstream = inputs
        .upstream
        .as_ref()
        .and_then(|dir| match read_upstream(dir) {
            Ok(upstream) => Some(upstream),
            Err(e) => {
                warnings.push(format!("the upstream facts are left out: {e:#}"));
                None
            }
        });
    if let Some(upstream) = &upstream {
        warnings.extend(upstream.warnings.iter().cloned());
    }
    let data = site_data(&ports, &channels, releases.as_deref(), upstream.as_ref());

    if src.exists() {
        fs::remove_dir_all(src).with_context(|| format!("removing {}", src.display()))?;
    }
    copy_tree(&site, src)?;
    let pages = src.join("content/plugins");
    for port in &ports {
        for (lang, _) in LANGS {
            let name = if lang == "ru" {
                format!("{}.md", port.short)
            } else {
                format!("{}.{lang}.md", port.short)
            };
            write(&pages.join(name), stub(&port.short).as_bytes())?;
        }
    }
    let mut json = serde_json::to_string_pretty(&data).context("serializing the site data")?;
    json.push('\n');
    let data_dir = src.join("data");
    fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
    write(&data_dir.join("site.json"), json.as_bytes())?;
    Ok(warnings)
}

/// `site/` holds only hand-written files.
fn check_site(site: &Path) -> anyhow::Result<()> {
    if !site.is_dir() {
        bail!("{} is missing", site.display());
    }
    let generated = || format!("generated content is not kept in {}", site.display());
    if site.join("data").exists() {
        bail!("{}: data/", generated());
    }
    let plugins = site.join("content/plugins");
    let entries =
        fs::read_dir(&plugins).with_context(|| format!("reading {}", plugins.display()))?;
    for entry in entries {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if !PLUGIN_INDEXES.contains(&name.as_ref()) {
            bail!("{}: content/plugins/{name}", generated());
        }
    }
    Ok(())
}

/// Copies `from` to `to`; a symbolic link is an error.
fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    let mut entries = fs::read_dir(from)
        .with_context(|| format!("reading {}", from.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading {}", from.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = fs::symlink_metadata(&path)
            .with_context(|| format!("reading {}", path.display()))?
            .file_type();
        let target = to.join(entry.file_name());
        if kind.is_symlink() {
            bail!("{} is a symbolic link", path.display());
        } else if kind.is_dir() {
            copy_tree(&path, &target)?;
        } else {
            fs::copy(&path, &target)
                .with_context(|| format!("copying {} to {}", path.display(), target.display()))?;
        }
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::Value;

    use super::*;

    fn fixtures() -> PathBuf {
        oncl_testkit::workspace_root().join("fixtures/registry")
    }

    /// A root with a minimal `site/`.
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let plugins = root.path().join("site/content/plugins");
        fs::create_dir_all(&plugins).unwrap();
        for name in PLUGIN_INDEXES {
            fs::write(plugins.join(name), "+++\n+++\n").unwrap();
        }
        fs::write(root.path().join("site/config.toml"), "").unwrap();
        root
    }

    fn all_inputs() -> Inputs {
        Inputs {
            plugins: fixtures().join("plugins"),
            updates: Some(fixtures().join("updates/v1")),
            releases: Some(fixtures().join("releases.jsonl")),
            upstream: Some(fixtures().join("upstream")),
        }
    }

    fn only_plugins() -> Inputs {
        Inputs {
            plugins: fixtures().join("plugins"),
            updates: None,
            releases: None,
            upstream: None,
        }
    }

    fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.insert(
                        path.strip_prefix(dir).unwrap().to_path_buf(),
                        fs::read(&path).unwrap(),
                    );
                }
            }
        }
        out
    }

    fn site_json(src: &Path) -> Value {
        serde_json::from_slice(&fs::read(src.join("data/site.json")).unwrap()).unwrap()
    }

    #[test]
    fn generate_is_deterministic() {
        let root = root();
        let out = tempfile::tempdir().unwrap();
        let (a, b) = (out.path().join("a"), out.path().join("b"));
        generate(root.path(), &all_inputs(), &a).unwrap();
        generate(root.path(), &all_inputs(), &b).unwrap();
        let (fa, fb) = (files(&a), files(&b));
        assert!(fa.len() > 10);
        assert_eq!(fa, fb);
    }

    #[test]
    fn generate_without_optional_inputs() {
        let root = root();
        let out = tempfile::tempdir().unwrap();
        let warnings = generate(root.path(), &only_plugins(), out.path()).unwrap();
        assert!(warnings.is_empty());
        let data = site_json(out.path());
        assert_eq!(data["releases"]["available"], false);
        assert_eq!(data["upstream"]["available"], false);
        assert_eq!(data["channels"], serde_json::json!({}));
        for (_, plugin) in data["plugins"].as_object().unwrap() {
            assert_eq!(plugin["original"]["state"], "unknown");
        }
    }

    #[test]
    fn stubs_carry_only_the_short_name() {
        let root = root();
        let out = tempfile::tempdir().unwrap();
        generate(root.path(), &all_inputs(), out.path()).unwrap();
        let pages = out.path().join("content/plugins");
        for short in ["alpha", "gamma", "hostile"] {
            let expected =
                format!("+++\ntemplate = \"plugin.html\"\n[extra]\nshort = \"{short}\"\n+++\n");
            for name in [
                format!("{short}.md"),
                format!("{short}.kk.md"),
                format!("{short}.en.md"),
            ] {
                assert_eq!(fs::read_to_string(pages.join(&name)).unwrap(), expected);
            }
        }
        // Every Markdown file of the build copy is a stub or a copy of `site/`.
        let site = files(&root.path().join("site"));
        for (path, bytes) in files(out.path()) {
            if path.extension().is_some_and(|e| e == "md") {
                let copied = site.get(&Path::new("").join(&path)) == Some(&bytes);
                let text = String::from_utf8(bytes).unwrap();
                assert!(
                    copied || text.starts_with("+++\ntemplate = \"plugin.html\""),
                    "{}",
                    path.display()
                );
                assert!(!text.contains("script"), "{}", path.display());
            }
        }
    }

    #[test]
    fn refuses_generated_files_in_site() {
        let root = root();
        let out = tempfile::tempdir().unwrap();
        fs::write(root.path().join("site/content/plugins/x.md"), "").unwrap();
        let err = generate(root.path(), &only_plugins(), out.path()).unwrap_err();
        assert!(err.to_string().contains("generated content"), "{err:#}");
        fs::remove_file(root.path().join("site/content/plugins/x.md")).unwrap();
        fs::create_dir(root.path().join("site/data")).unwrap();
        let err = generate(root.path(), &only_plugins(), out.path()).unwrap_err();
        assert!(err.to_string().contains("generated content"), "{err:#}");
    }

    #[test]
    fn broken_upstream_is_a_warning() {
        let root = root();
        let upstream = tempfile::tempdir().unwrap();
        fs::create_dir(upstream.path().join("latest")).unwrap();
        fs::write(upstream.path().join("latest/facts.json"), "{not json").unwrap();
        let releases = upstream.path().join("releases.jsonl");
        fs::write(&releases, "[1]\n").unwrap();
        let inputs = Inputs {
            upstream: Some(upstream.path().to_path_buf()),
            releases: Some(releases),
            ..only_plugins()
        };
        let out = tempfile::tempdir().unwrap();
        let warnings = generate(root.path(), &inputs, out.path()).unwrap();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        let data = site_json(out.path());
        assert_eq!(data["upstream"]["available"], false);
        assert_eq!(data["releases"]["available"], false);
    }

    #[test]
    fn broken_registry_is_an_error() {
        let root = root();
        let plugins = tempfile::tempdir().unwrap();
        copy_tree(&fixtures().join("plugins"), plugins.path()).unwrap();
        fs::write(plugins.path().join("gamma/registry.toml"), "id = 1\n").unwrap();
        let inputs = Inputs {
            plugins: plugins.path().to_path_buf(),
            ..only_plugins()
        };
        let out = tempfile::tempdir().unwrap();
        let err = generate(root.path(), &inputs, out.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("gamma/registry.toml"),
            "{err:#}"
        );
    }

    #[test]
    fn broken_index_is_an_error() {
        let root = root();
        let updates = tempfile::tempdir().unwrap();
        fs::write(updates.path().join("beta.json"), "{}").unwrap();
        let inputs = Inputs {
            updates: Some(updates.path().to_path_buf()),
            ..only_plugins()
        };
        let out = tempfile::tempdir().unwrap();
        let err = generate(root.path(), &inputs, out.path()).unwrap_err();
        assert!(format!("{err:#}").contains("beta.json"), "{err:#}");
    }
}
