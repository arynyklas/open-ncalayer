//! App-local DLLs built by this workspace: their export tables, and loading them the way an
//! executable loads a DLL that lies next to it (Windows only).

use std::ffi::{CStr, OsString};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use object::FileKind;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64};
use object::read::pe::{ExportTarget, ImageNtHeaders, PeFile};
use tempfile::TempDir;
use windows_sys::Win32::Foundation::{FARPROC, FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LoadLibraryExW,
};

/// The exports of the PE image `dll`, sorted by name: the name (`#<ordinal>` for an export by
/// ordinal only) and, for a forward, its target (`ole32.CoTaskMemFree`); `None` for code of
/// the DLL itself.
///
/// # Panics
///
/// If the file cannot be read or is not a valid PE image.
pub fn exports(dll: &Path) -> Vec<(String, Option<String>)> {
    let data = std::fs::read(dll).unwrap_or_else(|e| panic!("{}: {e}", dll.display()));
    let mut exports = match FileKind::parse(&*data).expect("a known file format") {
        FileKind::Pe32 => exports_of::<ImageNtHeaders32>(&data),
        FileKind::Pe64 => exports_of::<ImageNtHeaders64>(&data),
        kind => panic!("{}: not a PE image: {kind:?}", dll.display()),
    };
    exports.sort();
    exports
}

fn exports_of<Pe: ImageNtHeaders>(data: &[u8]) -> Vec<(String, Option<String>)> {
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let file = PeFile::<Pe>::parse(data).expect("a valid PE image");
    let Some(table) = file.export_table().expect("a valid export table") else {
        return Vec::new();
    };
    table
        .exports()
        .expect("valid exports")
        .into_iter()
        .map(|export| {
            let name = export
                .name
                .map_or_else(|| format!("#{}", export.ordinal), text);
            let target = match export.target {
                ExportTarget::Address(_) => None,
                ExportTarget::ForwardByName(dll, name) => {
                    Some(format!("{}.{}", text(dll), text(name)))
                }
                ExportTarget::ForwardByOrdinal(dll, ordinal) => {
                    Some(format!("{}.#{ordinal}", text(dll)))
                }
            };
            (name, target)
        })
        .collect()
}

/// Builds the cdylib of the workspace package `package` for the host target with the cargo
/// running the tests, into `target_dir`, and returns the path of the DLL. Pass the test's
/// `CARGO_TARGET_TMPDIR`, not the build directory of the running `cargo test`; cargo does not
/// tell a test where it put the package's library.
///
/// # Panics
///
/// If cargo fails or reports no DLL for the package.
pub fn build_cdylib(package: &str, target_dir: &Path) -> PathBuf {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(crate::workspace_root())
        .args([
            "build",
            "--message-format=json-render-diagnostics",
            "-p",
            package,
        ])
        .arg("--target-dir")
        .arg(target_dir)
        .stderr(Stdio::inherit())
        .output()
        .expect("running cargo");
    assert!(
        output.status.success(),
        "cargo build -p {package}: {}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 cargo messages");
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .find_map(|message| {
            message["filenames"]
                .as_array()?
                .iter()
                .filter_map(|name| name.as_str())
                .map(PathBuf::from)
                .find(|path| {
                    path.extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
                })
        })
        .unwrap_or_else(|| panic!("cargo build -p {package} reported no DLL"))
}

/// A DLL copied under its shipping name into a temporary directory and loaded from there by
/// its full path. Unloaded on drop.
pub struct AppLocalDll {
    module: HMODULE,
    _dir: TempDir,
}

impl AppLocalDll {
    /// Copies the DLL `source` to `<tempdir>/<name>` and loads it by that full path.
    ///
    /// # Panics
    ///
    /// If the DLL cannot be copied or does not load, or if the loader mapped some other file
    /// of that name instead of the copy (a system DLL, for instance).
    pub fn load(source: &Path, name: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::copy(source, &path)
            .unwrap_or_else(|e| panic!("copying {} to {}: {e}", source.display(), path.display()));
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `wide` is a NUL-terminated path; no file handle, no flags.
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0) };
        assert!(
            !module.is_null(),
            "LoadLibraryExW({}): {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        let dll = Self { module, _dir: dir };
        let mapped = module_path(module);
        let canonical =
            |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert_eq!(
            canonical(&mapped),
            canonical(&path),
            "the loader mapped another {name}"
        );
        dll
    }

    /// The address `GetProcAddress` gives for the export `name`, `None` if not exported.
    pub fn proc(&self, name: &CStr) -> FARPROC {
        // SAFETY: `self.module` stays loaded while `self` lives; `name` is NUL-terminated.
        unsafe { GetProcAddress(self.module, name.as_ptr().cast()) }
    }
}

impl Drop for AppLocalDll {
    fn drop(&mut self) {
        // SAFETY: `self.module` came from `LoadLibraryExW` and is freed once.
        unsafe { FreeLibrary(self.module) };
    }
}

/// The full path of a loaded module.
fn module_path(module: HMODULE) -> PathBuf {
    let mut buf = vec![0u16; 32 * 1024];
    let len = u32::try_from(buf.len()).expect("the buffer length fits u32");
    // SAFETY: `buf` holds `len` UTF-16 units.
    let written = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), len) };
    assert!(
        written != 0,
        "GetModuleFileNameW: {}",
        std::io::Error::last_os_error()
    );
    buf.truncate(written as usize);
    PathBuf::from(OsString::from_wide(&buf))
}
