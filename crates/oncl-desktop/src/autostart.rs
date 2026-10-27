//! Our autostart: an entry that runs `"<exe>" run` when the user logs in.
//!
//! - Windows: the value `OpenNCALayer` of `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//!   ([`RegistryAutostart`]);
//! - Linux: `~/.config/autostart/openncalayer.desktop` (`$XDG_CONFIG_HOME/autostart`;
//!   [`FileAutostart::desktop_entry`]);
//! - macOS: `~/Library/LaunchAgents/io.github.arynyklas.openncalayer.plist` with `RunAtLoad`
//!   ([`FileAutostart::launch_agent`]).
//!
//! Each is built from a root: the real one ([`current_user`]) or a sandbox for tests
//! ([`AutostartPaths::sandbox`], [`RegistryBase::sandbox`]).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::fsutil::write_atomic;

/// The launchd label of our LaunchAgent, also its file name.
const LAUNCH_AGENT_LABEL: &str = "io.github.arynyklas.openncalayer";

/// Our entry started at login.
pub trait Autostart {
    /// Whether the entry exists and is not disabled. The program it names is not compared
    /// with any: [`Autostart::set`] with `on` rewrites it for the given one.
    ///
    /// # Errors
    ///
    /// The entry cannot be read.
    fn enabled(&self) -> io::Result<bool>;

    /// Creates or replaces the entry so that it runs `"<exe>" run` (`on`), or removes it;
    /// removing a missing entry succeeds.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] if `exe` is not absolute, or cannot be written into
    /// the entry (not Unicode, or with control characters); any error writing the entry.
    fn set(&self, on: bool, exe: &Path) -> io::Result<()>;
}

/// The autostart of the user running this process, on this system.
///
/// # Errors
///
/// Linux and macOS: the home directory is unknown (`HOME` is not set).
pub fn current_user() -> io::Result<Box<dyn Autostart + Send + Sync>> {
    #[cfg(windows)]
    {
        Ok(Box::new(RegistryAutostart::new(
            RegistryBase::current_user(),
        )))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(FileAutostart::launch_agent(
            &AutostartPaths::detect()?,
        )))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(Box::new(FileAutostart::desktop_entry(
            &AutostartPaths::detect()?,
        )))
    }
}

/// The directories of the file-based entries: the home directory and the user's
/// configuration directory (`$XDG_CONFIG_HOME`, by default `~/.config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartPaths {
    home: PathBuf,
    config: PathBuf,
}

impl AutostartPaths {
    /// The directories of the user running this process.
    ///
    /// # Errors
    ///
    /// `HOME` is not set.
    #[cfg(unix)]
    pub fn detect() -> io::Result<AutostartPaths> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        // The XDG base directory specification ignores a relative path.
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|c| c.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Ok(AutostartPaths { home, config })
    }

    /// `root` as the home directory, with `root/.config` as the configuration directory.
    pub fn sandbox(root: &Path) -> AutostartPaths {
        AutostartPaths {
            home: root.to_owned(),
            config: root.join(".config"),
        }
    }

    /// `<config>/autostart/openncalayer.desktop`.
    pub fn desktop_entry(&self) -> PathBuf {
        self.config.join("autostart").join("openncalayer.desktop")
    }

    /// `<home>/Library/LaunchAgents/io.github.arynyklas.openncalayer.plist`.
    pub fn launch_agent(&self) -> PathBuf {
        self.home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LAUNCH_AGENT_LABEL}.plist"))
    }
}

/// An autostart entry in a file: an XDG desktop entry or a launchd LaunchAgent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileAutostart {
    path: PathBuf,
    kind: FileKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileKind {
    DesktopEntry,
    LaunchAgent,
}

impl FileAutostart {
    /// The XDG autostart desktop entry (Linux) under `paths`.
    pub fn desktop_entry(paths: &AutostartPaths) -> FileAutostart {
        FileAutostart {
            path: paths.desktop_entry(),
            kind: FileKind::DesktopEntry,
        }
    }

    /// The LaunchAgent (macOS) under `paths`.
    pub fn launch_agent(paths: &AutostartPaths) -> FileAutostart {
        FileAutostart {
            path: paths.launch_agent(),
            kind: FileKind::LaunchAgent,
        }
    }

    /// The entry's file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Autostart for FileAutostart {
    /// The file exists; a desktop entry also must not be hidden (`Hidden=true`, as KDE
    /// disables one) or disabled for GNOME (`X-GNOME-Autostart-enabled=false`).
    fn enabled(&self) -> io::Result<bool> {
        let text = match fs::read(&self.path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(match self.kind {
            FileKind::DesktopEntry => !desktop_entry_disabled(&text),
            FileKind::LaunchAgent => true,
        })
    }

    fn set(&self, on: bool, exe: &Path) -> io::Result<()> {
        if !on {
            return match fs::remove_file(&self.path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        let exe = entry_exe(exe)?;
        let text = match self.kind {
            FileKind::DesktopEntry => desktop_entry(exe),
            FileKind::LaunchAgent => launch_agent(exe),
        };
        write_atomic(&self.path, text.as_bytes())
    }
}

/// `exe` as text for an entry: absolute, Unicode, without control characters.
fn entry_exe(exe: &Path) -> io::Result<&str> {
    let invalid = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{why}: {}", exe.display()),
        )
    };
    if !exe.is_absolute() {
        return Err(invalid("the program path is not absolute"));
    }
    let text = exe
        .to_str()
        .ok_or_else(|| invalid("the program path is not Unicode"))?;
    if text.chars().any(char::is_control) {
        return Err(invalid("the program path has control characters"));
    }
    Ok(text)
}

/// The desktop entry running `"<exe>" run`.
fn desktop_entry(exe: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=OpenNCALayer\n\
         Comment=NCALayer-compatible signing service\n\
         Exec={} run\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        desktop_exec_arg(exe)
    )
}

/// `arg` as a quoted argument of a desktop entry's `Exec` key: `"`, `` ` ``, `$` and `\`
/// escaped with `\` inside the quotes, then every `\` doubled by the escaping of string
/// values, and `%` written `%%` so it is not a field code.
fn desktop_exec_arg(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted.replace('\\', "\\\\").replace('%', "%%")
}

/// Whether the `[Desktop Entry]` group of `text` hides the entry or disables it for GNOME.
fn desktop_entry_disabled(text: &str) -> bool {
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if in_entry
            && ((key == "Hidden" && value == "true")
                || (key == "X-GNOME-Autostart-enabled" && value == "false"))
        {
            return true;
        }
    }
    false
}

/// The LaunchAgent property list running `<exe> run` at login.
fn launch_agent(exe: &str) -> String {
    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n",
    );
    // Writing to a `String` cannot fail.
    let _ = write!(
        plist,
        "\t<key>Label</key>\n\t<string>{LAUNCH_AGENT_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\
         \t\t<string>{}</string>\n\t\t<string>run</string>\n\t</array>\n\
         \t<key>RunAtLoad</key>\n\t<true/>\n</dict>\n</plist>\n",
        xml_escape(exe)
    );
    plist
}

/// `text` with the XML special characters as entities.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Where the `Run` key is: `HKEY_CURRENT_USER` itself or, for tests, a key under it that
/// stands for it.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryBase {
    /// Prepended to the paths of keys under `HKEY_CURRENT_USER`; empty or ending in `\`.
    prefix: String,
}

#[cfg(windows)]
impl RegistryBase {
    /// `HKEY_CURRENT_USER`.
    pub fn current_user() -> RegistryBase {
        RegistryBase {
            prefix: String::new(),
        }
    }

    /// `HKEY_CURRENT_USER\<root>` in place of `HKEY_CURRENT_USER`, e.g.
    /// `Software\OpenNCALayer-test-<random>` (which the test deletes afterwards).
    pub fn sandbox(root: &str) -> RegistryBase {
        RegistryBase {
            prefix: format!("{}\\", root.trim_end_matches('\\')),
        }
    }

    /// The path of `key` (relative to `HKEY_CURRENT_USER`) under this base.
    pub fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

/// Our value of the `Run` key: `OpenNCALayer = "<exe>" run`.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryAutostart {
    run_key: String,
}

#[cfg(windows)]
impl RegistryAutostart {
    /// The `Run` key of the current user.
    pub const RUN_KEY: &'static str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    /// Our value's name.
    pub const VALUE: &'static str = "OpenNCALayer";

    /// Our value of the `Run` key under `base`.
    pub fn new(base: RegistryBase) -> RegistryAutostart {
        RegistryAutostart {
            run_key: base.key(Self::RUN_KEY),
        }
    }
}

#[cfg(windows)]
impl Autostart for RegistryAutostart {
    /// The value exists.
    fn enabled(&self) -> io::Result<bool> {
        crate::registry::get_string(&self.run_key, Some(Self::VALUE)).map(|v| v.is_some())
    }

    fn set(&self, on: bool, exe: &Path) -> io::Result<()> {
        if on {
            // A Windows path cannot hold `"`: quoting is enough.
            let command = format!("\"{}\" run", entry_exe(exe)?);
            crate::registry::set_string(&self.run_key, Some(Self::VALUE), &command)
        } else {
            crate::registry::delete_value(&self.run_key, Self::VALUE).map(drop)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An absolute program path on this system.
    fn exe(unix: &str, windows: &str) -> PathBuf {
        PathBuf::from(if cfg!(windows) { windows } else { unix })
    }

    #[test]
    fn desktop_entry_in_a_sandbox() {
        let d = tempfile::tempdir().unwrap();
        let paths = AutostartPaths::sandbox(d.path());
        let entry = FileAutostart::desktop_entry(&paths);
        assert_eq!(
            entry.path(),
            d.path().join(".config/autostart/openncalayer.desktop")
        );
        assert!(!entry.enabled().unwrap());
        // Turning off what is not there succeeds.
        entry.set(false, Path::new("")).unwrap();

        let program = exe("/opt/oncl/openncalayer", r"C:\oncl\openncalayer.exe");
        entry.set(true, &program).unwrap();
        assert!(entry.enabled().unwrap());
        let text = fs::read_to_string(entry.path()).unwrap();
        assert!(
            text.starts_with("[Desktop Entry]\nType=Application\n"),
            "{text}"
        );
        let exec = format!("Exec={} run\n", desktop_exec_arg(program.to_str().unwrap()));
        assert!(text.contains(&exec), "{text}");

        // Disabled from the desktop's own settings.
        for disabled in ["Hidden=true", "X-GNOME-Autostart-enabled = false"] {
            fs::write(entry.path(), format!("[Desktop Entry]\n{disabled}\n")).unwrap();
            assert!(!entry.enabled().unwrap(), "{disabled}");
        }
        // Keys of another group do not count.
        fs::write(
            entry.path(),
            "[Desktop Entry]\nType=Application\n[X]\nHidden=true\n",
        )
        .unwrap();
        assert!(entry.enabled().unwrap());

        entry.set(false, &program).unwrap();
        assert!(!entry.enabled().unwrap());
        assert!(!entry.path().exists());
        assert!(!entry.path().with_extension("desktop.tmp").exists());
    }

    #[test]
    fn exec_argument_is_quoted_and_escaped() {
        assert_eq!(desktop_exec_arg("/opt/a b/x"), r#""/opt/a b/x""#);
        // `$` → `\$` by quoting → `\\$` by string escaping; `\` → `\\` → `\\\\`.
        assert_eq!(
            desktop_exec_arg(r#"/a"b`c$d\e%f"#),
            r#""/a\\"b\\`c\\$d\\\\e%%f""#
        );
    }

    #[test]
    fn launch_agent_in_a_sandbox() {
        let d = tempfile::tempdir().unwrap();
        let agent = FileAutostart::launch_agent(&AutostartPaths::sandbox(d.path()));
        assert_eq!(
            agent.path(),
            d.path()
                .join("Library/LaunchAgents/io.github.arynyklas.openncalayer.plist")
        );
        assert!(!agent.enabled().unwrap());
        let program = exe(
            "/Applications/Open & Co <1>.app/Contents/MacOS/openncalayer",
            r"C:\Open & Co <1>\openncalayer.exe",
        );
        agent.set(true, &program).unwrap();
        assert!(agent.enabled().unwrap());
        let text = fs::read_to_string(agent.path()).unwrap();
        assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"), "{text}");
        assert!(
            text.contains("<string>io.github.arynyklas.openncalayer</string>"),
            "{text}"
        );
        let escaped = format!(
            "\t\t<string>{}</string>\n\t\t<string>run</string>\n",
            program
                .to_str()
                .unwrap()
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        );
        assert!(text.contains(&escaped), "{text}");
        agent.set(false, &program).unwrap();
        assert!(!agent.enabled().unwrap());
    }

    #[test]
    fn program_path_must_be_absolute_and_plain() {
        let d = tempfile::tempdir().unwrap();
        let entry = FileAutostart::desktop_entry(&AutostartPaths::sandbox(d.path()));
        let invalid = |exe: &Path| {
            entry
                .set(true, exe)
                .is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput)
        };
        assert!(invalid(Path::new("openncalayer")));
        assert!(invalid(&exe("/opt/a\nb", "C:\\a\nb")));
        assert!(!entry.path().exists());
    }

    #[cfg(windows)]
    #[test]
    fn run_value_under_a_test_key() {
        let root = crate::registry::TestKey::new();
        let base = RegistryBase::sandbox(&root.0);
        let run_key = base.key(RegistryAutostart::RUN_KEY);
        assert_eq!(
            run_key,
            format!(r"{}\Software\Microsoft\Windows\CurrentVersion\Run", root.0)
        );
        let autostart = RegistryAutostart::new(base);
        assert!(!autostart.enabled().unwrap());
        autostart.set(false, Path::new("")).unwrap();

        let program = Path::new(r"C:\Program Files\OpenNCALayer\openncalayer.exe");
        autostart.set(true, program).unwrap();
        assert!(autostart.enabled().unwrap());
        assert_eq!(
            crate::registry::get_string(&run_key, Some("OpenNCALayer"))
                .unwrap()
                .as_deref(),
            Some(r#""C:\Program Files\OpenNCALayer\openncalayer.exe" run"#)
        );
        assert!(
            autostart
                .set(true, Path::new("openncalayer.exe"))
                .is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput)
        );

        autostart.set(false, program).unwrap();
        assert!(!autostart.enabled().unwrap());
        // The rest of the sandbox stays until the test key goes.
        assert_eq!(crate::registry::get_string(&run_key, None).unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn real_base_is_hkcu_run() {
        assert_eq!(
            RegistryAutostart::new(RegistryBase::current_user()).run_key,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }
}
