//! The About window: the program's version, commit, licence and repository with Slint's
//! `AboutSlint`; the «Модули» tab with the bundles of `getBundles` and the daemon's modules;
//! the third-party licences of `assets/THIRD-PARTY.txt` (written by `cargo xtask licenses`),
//! parsed by [`parse_third_party`].

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::LazyLock;
use std::time::Duration;

use slint::{
    CloseRequestResponse, ComponentHandle, ModelRc, PlatformError, StandardListViewItem, VecModel,
};

use crate::foreground;
use crate::prompter::select_language;
use crate::ui::AboutWindow;
use crate::windows::Desktop;

/// The program's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The git commit of the build (`unknown` outside a git checkout).
pub const COMMIT: &str = env!("ONCL_GIT_COMMIT");
/// The project's repository.
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The third-party licences, as `cargo xtask licenses` writes them.
const THIRD_PARTY: &str = include_str!("../assets/THIRD-PARTY.txt");

/// What the «Модули» tab lists, from the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AboutInfo {
    /// `getBundles`: `(symname, version)`.
    pub bundles: Vec<(String, String)>,
    /// The modules of the daemon's registry.
    pub modules: Vec<String>,
}

/// The tab the About window shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AboutTab {
    Program,
    /// `showBundleManager`.
    Modules,
}

/// A third-party crate of the programs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThirdPartyCrate {
    pub name: String,
    pub version: String,
    /// The SPDX expression.
    pub license: String,
    pub repository: String,
    /// Indexes into [`ThirdParty::texts`].
    pub texts: Vec<usize>,
}

/// A licence text: its title and the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseText {
    pub title: String,
    pub text: String,
}

/// The third-party licences.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThirdParty {
    pub crates: Vec<ThirdPartyCrate>,
    pub texts: Vec<LicenseText>,
}

impl ThirdParty {
    /// The licence texts of the crate at `i`, one after another under their titles.
    pub fn texts_of(&self, i: usize) -> String {
        let Some(c) = self.crates.get(i) else {
            return String::new();
        };
        c.texts
            .iter()
            .filter_map(|&t| self.texts.get(t))
            .map(|t| format!("{}\n\n{}", t.title, t.text))
            .collect::<Vec<_>>()
            .join("\n\n\n")
    }
}

/// The embedded third-party licences, parsed on first use.
static PARSED: LazyLock<ThirdParty> = LazyLock::new(|| parse_third_party(THIRD_PARTY));

/// The embedded third-party licences.
pub fn third_party() -> &'static ThirdParty {
    &PARSED
}

/// The crates and texts of a file `cargo xtask licenses` wrote: after the `[crates]` line,
/// `name version | licence | repository | 1, 2` up to a blank line; then sections that
/// begin with `[text N] title`, numbered from 1, each followed by a blank line and its text.
/// Lines that do not fit are skipped.
pub fn parse_third_party(file: &str) -> ThirdParty {
    let mut parsed = ThirdParty::default();
    let mut lines = file.lines().skip_while(|l| *l != "[crates]").skip(1);
    for line in lines.by_ref().take_while(|l| !l.is_empty()) {
        let fields: Vec<&str> = line.split(" | ").collect();
        let [name_version, license, repository, texts] = fields[..] else {
            continue;
        };
        let Some((name, version)) = name_version.split_once(' ') else {
            continue;
        };
        parsed.crates.push(ThirdPartyCrate {
            name: name.to_owned(),
            version: version.to_owned(),
            license: license.to_owned(),
            repository: repository.to_owned(),
            texts: texts
                .split(", ")
                .filter_map(|n| n.parse::<usize>().ok()?.checked_sub(1))
                .collect(),
        });
    }
    let mut current: Option<(String, Vec<&str>)> = None;
    for line in lines {
        let next = format!(
            "[text {}] ",
            parsed.texts.len() + usize::from(current.is_some()) + 1
        );
        if let Some(title) = line.strip_prefix(&next) {
            parsed.texts.extend(current.take().map(finish));
            current = Some((title.to_owned(), Vec::new()));
        } else if let Some((_, body)) = &mut current {
            body.push(line);
        }
    }
    parsed.texts.extend(current.map(finish));
    parsed
}

/// A text section: its title, and its body without the blank lines around it.
fn finish((title, body): (String, Vec<&str>)) -> LicenseText {
    LicenseText {
        title,
        text: body.join("\n").trim_matches('\n').to_owned(),
    }
}

thread_local! {
    static OPEN: RefCell<Option<AboutWindow>> = const { RefCell::new(None) };
}

/// Shows the About window on `tab`, or brings the open one to the front there. On the event
/// loop.
pub(crate) fn open(desktop: &Rc<Desktop>, tab: AboutTab) {
    let tab = match tab {
        AboutTab::Program => 0,
        AboutTab::Modules => 1,
    };
    if let Some(ui) = current() {
        select_language(desktop.locale.get());
        ui.set_tab(tab);
        if let Err(e) = ui.show() {
            tracing::warn!(error = %e, "cannot show the About window");
        }
        foreground::take(&ui);
        return;
    }
    if let Err(e) = create(desktop, tab) {
        tracing::error!(error = %e, "cannot show the About window");
    }
}

/// The open About window, if any.
pub(crate) fn current() -> Option<AboutWindow> {
    OPEN.with_borrow(|open| open.as_ref().map(ComponentHandle::clone_strong))
}

fn create(desktop: &Desktop, tab: i32) -> Result<(), PlatformError> {
    let ui = AboutWindow::new()?;
    // After the window exists: the bundled translations come with it.
    select_language(desktop.locale.get());
    ui.set_tab(tab);
    ui.set_version(VERSION.into());
    ui.set_commit(COMMIT.into());
    ui.set_repository(REPOSITORY.into());
    ui.set_bundles(items(
        desktop
            .about
            .bundles
            .iter()
            .map(|(symname, version)| format!("{symname} {version}")),
    ));
    ui.set_modules(items(desktop.about.modules.iter().cloned()));
    let licences = third_party();
    ui.set_crates(items(
        licences
            .crates
            .iter()
            .map(|c| format!("{} {}", c.name, c.version)),
    ));
    let weak = ui.as_weak();
    ui.on_crate_chosen(move |i| {
        if let Some(ui) = weak.upgrade() {
            show_crate(&ui, i);
        }
    });
    if !licences.crates.is_empty() {
        ui.set_selected_crate(0);
        show_crate(&ui, 0);
    }
    ui.on_open_repository(open_repository);
    ui.on_dismiss(close);
    ui.window().on_close_requested(|| {
        close();
        CloseRequestResponse::HideWindow
    });
    OPEN.set(Some(ui.clone_strong()));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    Ok(())
}

/// The licence and texts of the crate at `i`.
fn show_crate(ui: &AboutWindow, i: i32) {
    let licences = third_party();
    let Some((i, c)) = usize::try_from(i)
        .ok()
        .and_then(|i| Some((i, licences.crates.get(i)?)))
    else {
        return;
    };
    ui.set_crate_license(
        format!("{} {}: {}\n{}", c.name, c.version, c.license, c.repository).into(),
    );
    ui.set_crate_texts(licences.texts_of(i).into());
}

/// Opens the repository in the default browser, off the event loop (a browser may take its
/// time to start).
fn open_repository() {
    let opened = std::thread::Builder::new()
        .name("browser".into())
        .spawn(|| {
            if let Err(e) = webbrowser::open(REPOSITORY) {
                tracing::warn!(error = %e, "cannot open the repository in a browser");
            }
        });
    if let Err(e) = opened {
        tracing::warn!(error = %e, "cannot open the repository in a browser");
    }
}

/// Closes the About window.
fn close() {
    let Some(ui) = OPEN.take() else {
        return;
    };
    if let Err(e) = ui.hide() {
        tracing::warn!(error = %e, "cannot hide the About window");
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(ui));
}

fn items(texts: impl Iterator<Item = String>) -> ModelRc<StandardListViewItem> {
    let items: Vec<StandardListViewItem> = texts
        .map(|t| StandardListViewItem::from(t.as_str()))
        .collect();
    ModelRc::new(VecModel::from(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_xtask_writes() {
        let file = "Title\n\n[crates]\n\
                    a 1.0.0 | MIT OR Apache-2.0 | https://example.test/a | 1, 2\n\
                    b 2.0.0 | MIT | - | 2\n\
                    broken line\n\
                    \n\
                    [text 1] LICENSE-APACHE of a 1.0.0\n\
                    \n\
                    Apache text\n\
                    [text 9] not a section\n\
                    \n\
                    [text 2] LICENSE-MIT of a 1.0.0\n\
                    \n\
                    MIT text\n\
                    \n\
                    second paragraph\n";
        let parsed = parse_third_party(file);
        assert_eq!(parsed.crates.len(), 2);
        assert_eq!(parsed.crates[0].name, "a");
        assert_eq!(parsed.crates[0].license, "MIT OR Apache-2.0");
        assert_eq!(parsed.crates[0].texts, [0, 1]);
        assert_eq!(parsed.crates[1].repository, "-");
        assert_eq!(parsed.texts.len(), 2);
        assert_eq!(parsed.texts[0].text, "Apache text\n[text 9] not a section");
        assert_eq!(parsed.texts[1].text, "MIT text\n\nsecond paragraph");
        assert_eq!(
            parsed.texts_of(1),
            "LICENSE-MIT of a 1.0.0\n\nMIT text\n\nsecond paragraph"
        );
        assert_eq!(parsed.texts_of(5), "");
    }

    /// Every crate of the embedded file has texts, every reference resolves, and Slint's
    /// royalty-free licence, under which OpenNCALayer uses it, is there.
    #[test]
    fn embedded_licences_are_complete() {
        let tp = third_party();
        assert!(tp.crates.len() > 100, "{}", tp.crates.len());
        for c in &tp.crates {
            assert!(!c.texts.is_empty(), "{} {}", c.name, c.version);
            assert!(
                c.texts.iter().all(|&t| t < tp.texts.len()),
                "{} {}",
                c.name,
                c.version
            );
        }
        assert_eq!(
            tp.texts.len(),
            THIRD_PARTY
                .lines()
                .filter(|l| l.starts_with("[text "))
                .count()
        );
        let slint = tp.crates.iter().position(|c| c.name == "slint").unwrap();
        assert!(tp.texts_of(slint).contains("Royalty-free"));
    }
}
