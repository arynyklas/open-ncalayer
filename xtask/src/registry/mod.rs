//! The plugin registry: the ports of `plugins/` and what the project says about them, and
//! the project site that shows it (`site/`, built with Zola into `target/site/`).

use std::path::PathBuf;

use oncl_basics::Locale;

pub mod check;
pub mod data;
pub mod generate;
pub mod inputs;
pub mod ports;
pub mod site;

pub use check::check;
pub use generate::generate;

/// The site's hand-written sources, from the workspace root.
pub const SITE_DIR: &str = "site";

/// The site's languages: the directory name (none for the default, `ru`) and the locale.
pub const LANGS: [(&str, Locale); 3] = [("ru", Locale::Ru), ("kk", Locale::Kk), ("en", Locale::En)];

/// What the site is generated from.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The ports: `plugins/`.
    pub plugins: PathBuf,
    /// The update indexes: `updates/v1/`, if there are any.
    pub updates: Option<PathBuf>,
    /// The project's releases, JSON Lines.
    pub releases: Option<PathBuf>,
    /// A copy of the `upstream` branch's `index.json` and `latest/facts.json`.
    pub upstream: Option<PathBuf>,
}
