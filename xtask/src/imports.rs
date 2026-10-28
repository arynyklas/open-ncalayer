//! PE import gate of the Windows 7 builds (roadmap D14): `cargo xtask check-imports` lists the
//! imports of each executable and fails on DLLs and functions that Windows 7 does not have.
//!
//! Two DLLs Windows 7 lacks ship next to the executables instead ([`APP_LOCAL_DLLS`]): before
//! Windows 8 the loader finds them in the executable's own directory. An import from one of
//! them passes only if the file of that name next to the executable exports exactly that name,
//! and that file is checked too: it has the executable's bitness and imports from and
//! forwards to [`APP_LOCAL_TARGETS`] only.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64};
use object::read::pe::{ExportTarget, ImageNtHeaders, PeFile};
use object::{FileKind, NameOrOrdinal, Object as _};

/// DLLs that do not exist on Windows 7: any import from them fails the gate.
const FORBIDDEN_DLLS: &[&str] = &["combase.dll", "api-ms-win-core-synch-l1-2-0.dll"];

/// DLL name prefixes of API sets that Windows 7 does not have.
const FORBIDDEN_DLL_PREFIXES: &[&str] = &["api-ms-win-core-winrt-"];

/// Functions that Windows 7 versions of these DLLs do not export.
const FORBIDDEN_FUNCTIONS: &[(&str, &str)] = &[
    ("bcryptprimitives.dll", "ProcessPrng"),
    ("kernel32.dll", "GetSystemTimePreciseAsFileTime"),
    // Windows 10 1607+.
    ("user32.dll", "SystemParametersInfoForDpi"),
];

/// DLLs that Windows 7 lacks and the Windows 7 builds carry next to their executables.
///
/// Windows 8 and later never load these copies: there `combase.dll` is a known DLL, and
/// `api-ms-win-*` names resolve through the system's API set schema.
pub const APP_LOCAL_DLLS: &[&str] = &["combase.dll", "api-ms-win-core-winrt-error-l1-1-0.dll"];

/// The only DLLs an app-local DLL may import from or forward to.
pub const APP_LOCAL_TARGETS: &[&str] = &["kernel32.dll", "ole32.dll"];

/// One imported function of a PE image, from the regular or the delay-load import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// DLL name as written in the import descriptor.
    pub dll: String,
    /// Function name; `None` for an import by ordinal.
    pub symbol: Option<String>,
}

/// One exported function of a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Export name; `None` for an export by ordinal only.
    pub name: Option<String>,
    /// For a forward, the function it resolves to: the forward `ole32.CoTaskMemFree` is
    /// `ole32.dll!CoTaskMemFree`. `None` for code of the image itself.
    pub forward: Option<Import>,
}

/// What the gate reads of a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// PE32+ (64-bit) rather than PE32 (32-bit).
    pub pe64: bool,
    /// Regular and delay-load imports.
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}

impl Image {
    /// Whether the image exports exactly the name `symbol`: the loader compares the bytes, so
    /// `_CoTaskMemFree@4` does not satisfy an import of `CoTaskMemFree`.
    fn exports_name(&self, symbol: &str) -> bool {
        self.exports
            .iter()
            .any(|export| export.name.as_deref() == Some(symbol))
    }
}

/// An app-local DLL ([`APP_LOCAL_DLLS`]) found next to an executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLocalDll {
    /// File name, one of [`APP_LOCAL_DLLS`].
    pub name: &'static str,
    pub image: Image,
}

/// Reads the bitness, the regular and delay-load imports and the exports of a PE32 or PE32+
/// image.
pub fn read_image(pe: &[u8]) -> anyhow::Result<Image> {
    match FileKind::parse(pe).context("unrecognized file format")? {
        FileKind::Pe32 => image_of::<ImageNtHeaders32>(pe),
        FileKind::Pe64 => image_of::<ImageNtHeaders64>(pe),
        kind => anyhow::bail!("not a PE image: {kind:?}"),
    }
}

fn image_of<Pe: ImageNtHeaders>(pe: &[u8]) -> anyhow::Result<Image> {
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let file = PeFile::<Pe>::parse(pe).context("invalid PE image")?;
    let imports = file
        .imports()
        .context("invalid PE import table")?
        .map(|import| {
            let import = import.context("invalid PE import")?;
            Ok(Import {
                dll: text(import.library()),
                symbol: match import.name() {
                    NameOrOrdinal::Name(name) => Some(text(name)),
                    NameOrOrdinal::Ordinal(_) => None,
                },
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let exports = match file.export_table().context("invalid PE export table")? {
        None => Vec::new(),
        Some(table) => table
            .exports()
            .context("invalid PE exports")?
            .into_iter()
            .map(|export| Export {
                name: export.name.map(text),
                // A forward names the DLL without its `.dll`, which the loader appends.
                forward: match export.target {
                    ExportTarget::Address(_) => None,
                    ExportTarget::ForwardByName(dll, name) => Some(Import {
                        dll: format!("{}.dll", text(dll)),
                        symbol: Some(text(name)),
                    }),
                    ExportTarget::ForwardByOrdinal(dll, _) => Some(Import {
                        dll: format!("{}.dll", text(dll)),
                        symbol: None,
                    }),
                },
            })
            .collect(),
    };
    Ok(Image {
        pe64: file.is_64(),
        imports,
        exports,
    })
}

/// The name without the decoration of a 32-bit x86 `__stdcall` (`_Name@8`, also `Name@8`) or
/// `__fastcall` (`@Name@8`) symbol; any other name as is.
fn undecorated(symbol: &str) -> &str {
    let Some((head, arguments)) = symbol.rsplit_once('@') else {
        return symbol;
    };
    if arguments.is_empty() || !arguments.bytes().all(|b| b.is_ascii_digit()) {
        return symbol;
    }
    let name = head.strip_prefix(['_', '@']).unwrap_or(head);
    if name.is_empty() { symbol } else { name }
}

/// What Windows 7 lacks for `import`: `"DLL"` or `"function"`; `None` if not on the denylist.
///
/// DLL names compare case-insensitively, function names exactly (PE exports are case-sensitive)
/// after removing the x86 decoration, so `_SystemParametersInfoForDpi@20` is caught as well.
fn missing_on_windows7(import: &Import) -> Option<&'static str> {
    let dll = &import.dll;
    if FORBIDDEN_DLLS
        .iter()
        .any(|forbidden| dll.eq_ignore_ascii_case(forbidden))
        || FORBIDDEN_DLL_PREFIXES.iter().any(|prefix| {
            dll.as_bytes()
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
        })
    {
        return Some("DLL");
    }
    let function = import.symbol.as_deref().map(undecorated)?;
    FORBIDDEN_FUNCTIONS
        .iter()
        .any(|(forbidden_dll, forbidden)| {
            dll.eq_ignore_ascii_case(forbidden_dll) && function == *forbidden
        })
        .then_some("function")
}

fn bitness(pe64: bool) -> &'static str {
    if pe64 { "PE32+" } else { "PE32" }
}

/// Describes every import of the executable `exe` that Windows 7 cannot satisfy, one line per
/// import, given the app-local DLLs next to it.
///
/// An import from an app-local DLL passes if that DLL exports exactly its name; an app-local
/// DLL of the other bitness is a violation of its own, since the loader cannot map it.
pub fn violations(exe: &Image, app_local: &[AppLocalDll]) -> Vec<String> {
    let wrong_bitness = app_local
        .iter()
        .filter(|dll| dll.image.pe64 != exe.pe64)
        .map(|dll| {
            format!(
                "{}: {} next to a {} executable",
                dll.name,
                bitness(dll.image.pe64),
                bitness(exe.pe64)
            )
        });
    let imports = exe.imports.iter().filter_map(|import| {
        let symbol = import.symbol.as_deref().unwrap_or("<ordinal>");
        if let Some(dll) = app_local
            .iter()
            .find(|dll| import.dll.eq_ignore_ascii_case(dll.name))
        {
            return match &import.symbol {
                Some(name) if dll.image.exports_name(name) => None,
                _ => Some(format!(
                    "{}!{symbol}: the app-local {} does not export it",
                    import.dll, dll.name
                )),
            };
        }
        let missing = missing_on_windows7(import)?;
        Some(format!(
            "{}!{symbol}: {missing} is missing on Windows 7",
            import.dll
        ))
    });
    wrong_bitness.chain(imports).collect()
}

/// Describes every import and forward of the app-local DLL `dll` that goes outside
/// [`APP_LOCAL_TARGETS`], is by ordinal, is missing on Windows 7, or names an x86-decorated
/// symbol (those DLLs export undecorated names only), one line each.
pub fn app_local_violations(dll: &AppLocalDll) -> Vec<String> {
    let imports = dll.image.imports.iter().map(|import| ("imports", import));
    let forwards = dll
        .image
        .exports
        .iter()
        .filter_map(|export| Some(("forwards to", export.forward.as_ref()?)));
    imports
        .chain(forwards)
        .filter_map(|(link, target)| {
            let symbol = target.symbol.as_deref().unwrap_or("<ordinal>");
            let problem = if !APP_LOCAL_TARGETS
                .iter()
                .any(|allowed| target.dll.eq_ignore_ascii_case(allowed))
            {
                format!("only {} are allowed", APP_LOCAL_TARGETS.join(" and "))
            } else if target.symbol.is_none() {
                "only by name".to_owned()
            } else if let Some(missing) = missing_on_windows7(target) {
                format!("{missing} is missing on Windows 7")
            } else if undecorated(symbol) != symbol {
                format!(
                    "{} export undecorated names only",
                    APP_LOCAL_TARGETS.join(" and ")
                )
            } else {
                return None;
            };
            Some(format!(
                "{} {link} {}!{symbol}: {problem}",
                dll.name, target.dll
            ))
        })
        .collect()
}

fn read_file(path: &Path) -> anyhow::Result<Image> {
    let pe = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    read_image(&pe).with_context(|| format!("parsing {}", path.display()))
}

/// The app-local DLLs in `dir`.
fn app_local_dlls(dir: &Path) -> anyhow::Result<Vec<AppLocalDll>> {
    APP_LOCAL_DLLS
        .iter()
        .map(|&name| (name, dir.join(name)))
        .filter(|(_, path)| path.is_file())
        .map(|(name, path)| {
            Ok(AppLocalDll {
                name,
                image: read_file(&path)?,
            })
        })
        .collect()
}

/// Prints the violations of each executable and of the app-local DLLs next to it to stdout
/// and returns their total count.
pub fn check_imports(exes: &[impl AsRef<Path>]) -> anyhow::Result<usize> {
    let mut total = 0;
    let mut checked_dirs: Vec<PathBuf> = Vec::new();
    for exe in exes {
        let exe = exe.as_ref();
        let image = read_file(exe)?;
        let dir = exe.parent().unwrap_or(Path::new(""));
        let app_local = app_local_dlls(dir)?;
        let found = violations(&image, &app_local);
        let from_app_local = image
            .imports
            .iter()
            .filter(|import| {
                app_local
                    .iter()
                    .any(|dll| import.dll.eq_ignore_ascii_case(dll.name))
            })
            .count();
        println!(
            "{}: {} forbidden of {} imports, {from_app_local} from app-local DLLs",
            exe.display(),
            found.len(),
            image.imports.len()
        );
        for violation in &found {
            println!("  {violation}");
        }
        total += found.len();
        if checked_dirs.iter().any(|checked| checked == dir) {
            continue;
        }
        checked_dirs.push(dir.to_owned());
        for dll in &app_local {
            let found = app_local_violations(dll);
            let forwards = dll
                .image
                .exports
                .iter()
                .filter(|export| export.forward.is_some())
                .count();
            println!(
                "{} (app-local): {} forbidden of {} imports and {forwards} forwards",
                dir.join(dll.name).display(),
                found.len(),
                dll.image.imports.len()
            );
            for violation in &found {
                println!("  {violation}");
            }
            total += found.len();
        }
    }
    Ok(total)
}

/// [`check_imports`] for an executable that is installed without the app-local DLLs: prints
/// its violations as if none were next to it and returns their count.
pub fn check_imports_alone(exe: &Path) -> anyhow::Result<usize> {
    let image = read_file(exe)?;
    let found = violations(&image, &[]);
    println!(
        "{} (without app-local DLLs): {} forbidden of {} imports",
        exe.display(),
        found.len(),
        image.imports.len()
    );
    for violation in &found {
        println!("  {violation}");
    }
    Ok(found.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imp(dll: &str, symbol: &str) -> Import {
        Import {
            dll: dll.to_owned(),
            symbol: Some(symbol.to_owned()),
        }
    }

    fn by_ordinal(dll: &str) -> Import {
        Import {
            dll: dll.to_owned(),
            symbol: None,
        }
    }

    fn exe(imports: &[Import]) -> Image {
        Image {
            pe64: true,
            imports: imports.to_vec(),
            exports: Vec::new(),
        }
    }

    fn forward(name: &str, dll: &str, symbol: &str) -> Export {
        Export {
            name: Some(name.to_owned()),
            forward: Some(imp(dll, symbol)),
        }
    }

    fn code(name: &str) -> Export {
        Export {
            name: Some(name.to_owned()),
            forward: None,
        }
    }

    /// The two app-local DLLs as the Windows 7 builds ship them.
    fn shipped(pe64: bool) -> Vec<AppLocalDll> {
        let image = |exports| Image {
            pe64,
            imports: vec![imp("KERNEL32.dll", "HeapFree")],
            exports,
        };
        vec![
            AppLocalDll {
                name: "combase.dll",
                image: image(vec![
                    forward(
                        "CoCreateFreeThreadedMarshaler",
                        "ole32.dll",
                        "CoCreateFreeThreadedMarshaler",
                    ),
                    forward("CoTaskMemFree", "ole32.dll", "CoTaskMemFree"),
                ]),
            },
            AppLocalDll {
                name: "api-ms-win-core-winrt-error-l1-1-0.dll",
                image: image(vec![code("RoOriginateError"), code("RoOriginateErrorW")]),
            },
        ]
    }

    #[test]
    fn flags_combase_and_win8_apis() {
        let v = violations(
            &exe(&[
                imp("COMBASE.dll", "CoTaskMemFree"),
                imp("kernel32.dll", "GetSystemTimePreciseAsFileTime"),
                imp("kernel32.dll", "CreateFileW"),
            ]),
            &[],
        );
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn flags_every_forbidden_entry_case_insensitively() {
        let v = violations(
            &exe(&[
                by_ordinal("combase.DLL"),
                imp("API-MS-WIN-CORE-SYNCH-L1-2-0.dll", "WaitOnAddress"),
                imp("BCryptPrimitives.dll", "ProcessPrng"),
                imp("KERNEL32.DLL", "GetSystemTimePreciseAsFileTime"),
                imp("USER32.dll", "SystemParametersInfoForDpi"),
                imp(
                    "api-ms-win-core-winrt-error-l1-1-0.dll",
                    "RoOriginateErrorW",
                ),
                imp("API-MS-WIN-CORE-WINRT-L1-1-0.DLL", "RoInitialize"),
            ]),
            &[],
        );
        assert_eq!(
            v,
            [
                "combase.DLL!<ordinal>: DLL is missing on Windows 7",
                "API-MS-WIN-CORE-SYNCH-L1-2-0.dll!WaitOnAddress: DLL is missing on Windows 7",
                "BCryptPrimitives.dll!ProcessPrng: function is missing on Windows 7",
                "KERNEL32.DLL!GetSystemTimePreciseAsFileTime: function is missing on Windows 7",
                "USER32.dll!SystemParametersInfoForDpi: function is missing on Windows 7",
                "api-ms-win-core-winrt-error-l1-1-0.dll!RoOriginateErrorW: DLL is missing on Windows 7",
                "API-MS-WIN-CORE-WINRT-L1-1-0.DLL!RoInitialize: DLL is missing on Windows 7",
            ]
        );
    }

    #[test]
    fn allows_windows7_imports() {
        let v = violations(
            &exe(&[
                imp("kernel32.dll", "GetSystemTimeAsFileTime"),
                imp("kernel32.dll", "getsystemtimepreciseasfiletime"),
                imp("advapi32.dll", "SystemFunction036"),
                imp("bcryptprimitives.dll", "ProcessPrngEx"),
                imp(
                    "api-ms-win-core-synch-l1-1-0.dll",
                    "AcquireSRWLockExclusive",
                ),
                imp("ole32.dll", "CoTaskMemFree"),
                imp("user32.dll", "SystemParametersInfoW"),
                imp("api-ms-win-core-winrt", "RoInitialize"),
                imp(
                    "ext-ms-win-core-winrt-error-l1-1-0.dll",
                    "RoOriginateErrorW",
                ),
            ]),
            &[],
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn flags_decorated_x86_names() {
        let v = violations(
            &exe(&[
                imp("user32.dll", "_SystemParametersInfoForDpi@20"),
                imp("kernel32.dll", "GetSystemTimePreciseAsFileTime@4"),
                imp("bcryptprimitives.dll", "@ProcessPrng@8"),
                imp("user32.dll", "_SystemParametersInfoW@16"),
                imp("kernel32.dll", "_GetSystemTimeAsFileTime@4"),
            ]),
            &[],
        );
        assert_eq!(
            v,
            [
                "user32.dll!_SystemParametersInfoForDpi@20: function is missing on Windows 7",
                "kernel32.dll!GetSystemTimePreciseAsFileTime@4: function is missing on Windows 7",
                "bcryptprimitives.dll!@ProcessPrng@8: function is missing on Windows 7",
            ]
        );
    }

    #[test]
    fn undecorates_only_x86_call_decorations() {
        for (symbol, name) in [
            ("_CoTaskMemFree@4", "CoTaskMemFree"),
            ("CoTaskMemFree@4", "CoTaskMemFree"),
            ("@CoTaskMemFree@4", "CoTaskMemFree"),
            ("_CoTaskMemFree@0", "CoTaskMemFree"),
            ("CoTaskMemFree", "CoTaskMemFree"),
            ("_CoTaskMemFree", "_CoTaskMemFree"),
            ("CoTaskMemFree@", "CoTaskMemFree@"),
            ("CoTaskMemFree@x4", "CoTaskMemFree@x4"),
            ("_@4", "_@4"),
            ("@4", "@4"),
        ] {
            assert_eq!(undecorated(symbol), name, "{symbol}");
        }
    }

    #[test]
    fn app_local_dll_satisfies_exactly_its_exports() {
        let v = violations(
            &exe(&[
                imp("COMBASE.dll", "CoTaskMemFree"),
                imp("combase.dll", "CoCreateFreeThreadedMarshaler"),
                imp(
                    "api-ms-win-core-winrt-error-l1-1-0.dll",
                    "RoOriginateErrorW",
                ),
                imp("combase.dll", "CoTaskMemAlloc"),
                imp("combase.dll", "_CoTaskMemFree@4"),
                imp("combase.dll", "cotaskmemfree"),
                by_ordinal("combase.dll"),
                imp(
                    "api-ms-win-core-winrt-error-l1-1-1.dll",
                    "RoOriginateLanguageException",
                ),
                imp("user32.dll", "SystemParametersInfoForDpi"),
            ]),
            &shipped(true),
        );
        assert_eq!(
            v,
            [
                "combase.dll!CoTaskMemAlloc: the app-local combase.dll does not export it",
                "combase.dll!_CoTaskMemFree@4: the app-local combase.dll does not export it",
                "combase.dll!cotaskmemfree: the app-local combase.dll does not export it",
                "combase.dll!<ordinal>: the app-local combase.dll does not export it",
                "api-ms-win-core-winrt-error-l1-1-1.dll!RoOriginateLanguageException: DLL is missing on Windows 7",
                "user32.dll!SystemParametersInfoForDpi: function is missing on Windows 7",
            ]
        );
    }

    #[test]
    fn app_local_dll_of_the_other_bitness_fails() {
        let imports = [imp("combase.dll", "CoTaskMemFree")];
        let pe32 = Image {
            pe64: false,
            ..exe(&imports)
        };
        assert!(violations(&pe32, &shipped(false)).is_empty());
        assert_eq!(
            violations(&pe32, &shipped(true)),
            [
                "combase.dll: PE32+ next to a PE32 executable",
                "api-ms-win-core-winrt-error-l1-1-0.dll: PE32+ next to a PE32 executable",
            ]
        );
        assert_eq!(
            violations(&exe(&imports), &shipped(false))[..1],
            ["combase.dll: PE32 next to a PE32+ executable"]
        );
    }

    #[test]
    fn shipped_app_local_dlls_are_clean() {
        for dll in shipped(true) {
            assert!(app_local_violations(&dll).is_empty(), "{}", dll.name);
        }
    }

    #[test]
    fn app_local_dll_uses_only_kernel32_and_ole32_by_undecorated_name() {
        let dll = AppLocalDll {
            name: "combase.dll",
            image: Image {
                pe64: true,
                imports: vec![
                    imp("KERNEL32.dll", "HeapFree"),
                    imp("kernel32.dll", "_HeapAlloc@12"),
                    imp("kernel32.dll", "_GetSystemTimePreciseAsFileTime@4"),
                    imp("user32.dll", "MessageBoxW"),
                    by_ordinal("ntdll.dll"),
                    by_ordinal("ole32.dll"),
                ],
                exports: vec![
                    forward("CoTaskMemFree", "OLE32.dll", "CoTaskMemFree"),
                    forward(
                        "CoCreateFreeThreadedMarshaler",
                        "ole32.dll",
                        "_CoCreateFreeThreadedMarshaler@8",
                    ),
                    forward("CoTaskMemAlloc", "combase.dll", "CoTaskMemAlloc"),
                    Export {
                        name: Some("CoInitialize".to_owned()),
                        forward: Some(by_ordinal("ole32.dll")),
                    },
                    code("DllMain"),
                ],
            },
        };
        assert_eq!(
            app_local_violations(&dll),
            [
                "combase.dll imports kernel32.dll!_HeapAlloc@12: kernel32.dll and ole32.dll export undecorated names only",
                "combase.dll imports kernel32.dll!_GetSystemTimePreciseAsFileTime@4: function is missing on Windows 7",
                "combase.dll imports user32.dll!MessageBoxW: only kernel32.dll and ole32.dll are allowed",
                "combase.dll imports ntdll.dll!<ordinal>: only kernel32.dll and ole32.dll are allowed",
                "combase.dll imports ole32.dll!<ordinal>: only by name",
                "combase.dll forwards to ole32.dll!_CoCreateFreeThreadedMarshaler@8: kernel32.dll and ole32.dll export undecorated names only",
                "combase.dll forwards to combase.dll!CoTaskMemAlloc: only kernel32.dll and ole32.dll are allowed",
                "combase.dll forwards to ole32.dll!<ordinal>: only by name",
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn reads_own_imports() {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let image = read_image(&me).unwrap();
        assert_eq!(image.pe64, cfg!(target_pointer_width = "64"));
        assert!(
            image
                .imports
                .iter()
                .any(|i| i.dll.eq_ignore_ascii_case("kernel32.dll"))
        );
    }

    #[test]
    fn reads_regular_and_delay_load_imports_of_pe32_and_pe64() {
        for pe64 in [false, true] {
            let pe = synthetic_pe(
                pe64,
                &[
                    (
                        "KERNEL32.dll",
                        &["CreateFileW", "GetSystemTimePreciseAsFileTime"],
                    ),
                    ("combase.dll", &["#7"]),
                ],
                &[("bcryptprimitives.dll", &["ProcessPrng"])],
                &[],
            );
            let image = read_image(&pe).unwrap();
            assert_eq!(image.pe64, pe64);
            assert_eq!(
                image.imports,
                [
                    imp("KERNEL32.dll", "CreateFileW"),
                    imp("KERNEL32.dll", "GetSystemTimePreciseAsFileTime"),
                    by_ordinal("combase.dll"),
                    imp("bcryptprimitives.dll", "ProcessPrng"),
                ],
                "pe64 = {pe64}"
            );
            assert!(image.exports.is_empty(), "pe64 = {pe64}");
            assert_eq!(violations(&image, &[]).len(), 3, "pe64 = {pe64}");
        }
    }

    #[test]
    fn reads_exports_and_forwards_of_pe32_and_pe64() {
        for pe64 in [false, true] {
            let pe = synthetic_pe(
                pe64,
                &[("KERNEL32.dll", &["HeapFree"])],
                &[],
                &[
                    ("CoTaskMemFree", Some("ole32.CoTaskMemFree")),
                    ("RoOriginateErrorW", None),
                ],
            );
            let image = read_image(&pe).unwrap();
            assert_eq!(
                image.exports,
                [
                    forward("CoTaskMemFree", "ole32.dll", "CoTaskMemFree"),
                    code("RoOriginateErrorW"),
                ],
                "pe64 = {pe64}"
            );
            let dll = AppLocalDll {
                name: "combase.dll",
                image,
            };
            assert!(app_local_violations(&dll).is_empty(), "pe64 = {pe64}");
        }
    }

    #[test]
    fn image_without_imports_is_clean() {
        for pe64 in [false, true] {
            let image = read_image(&synthetic_pe(pe64, &[], &[], &[])).unwrap();
            assert!(image.imports.is_empty());
            assert!(image.exports.is_empty());
        }
    }

    #[test]
    fn rejects_non_pe_input() {
        assert!(read_image(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0").is_err());
        assert!(read_image(b"not an executable").is_err());
        let mut truncated = synthetic_pe(true, &[("kernel32.dll", &["CreateFileW"])], &[], &[]);
        truncated.truncate(0x100);
        assert!(read_image(&truncated).is_err());
    }

    #[test]
    fn checks_the_app_local_dlls_next_to_each_executable() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, pe: Vec<u8>| std::fs::write(dir.path().join(name), pe).unwrap();
        let combase_imports: &[(&str, &[&str])] = &[("combase.dll", &["CoTaskMemFree"])];
        write("app.exe", synthetic_pe(true, combase_imports, &[], &[]));
        let app = dir.path().join("app.exe");
        // Without the DLL next to it.
        assert_eq!(check_imports(&[&app]).unwrap(), 1);
        write(
            "combase.dll",
            synthetic_pe(
                true,
                &[("kernel32.dll", &["HeapFree"])],
                &[],
                &[("CoTaskMemFree", Some("ole32.CoTaskMemFree"))],
            ),
        );
        assert_eq!(check_imports(&[&app]).unwrap(), 0);
        // A 32-bit executable next to it, and a DLL that is not app-local.
        write("app32.exe", synthetic_pe(false, combase_imports, &[], &[]));
        write(
            "other.dll",
            synthetic_pe(true, &[("user32.dll", &["X"])], &[], &[]),
        );
        assert_eq!(
            check_imports(&[&app, &dir.path().join("app32.exe")]).unwrap(),
            1
        );
        // The DLL forwards outside kernel32 and ole32.
        write(
            "combase.dll",
            synthetic_pe(
                true,
                &[],
                &[],
                &[("CoTaskMemFree", Some("combase.CoTaskMemFree"))],
            ),
        );
        assert_eq!(check_imports(&[&app]).unwrap(), 1);
    }

    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = 0x200;

    /// Builds a minimal PE image whose single section holds the import and export tables.
    /// Each import entry is a DLL with its symbols; `#N` imports ordinal `N`. Each export is a
    /// name with its forward (`ole32.CoTaskMemFree`), or `None` for code at the section start.
    fn synthetic_pe(
        pe64: bool,
        imports: &[(&str, &[&str])],
        delay: &[(&str, &[&str])],
        exports: &[(&str, Option<&str>)],
    ) -> Vec<u8> {
        const DESCRIPTOR: usize = 20;
        const DELAY_DESCRIPTOR: usize = 32;
        let delay_start = (imports.len() + 1) * DESCRIPTOR;
        let mut sec = vec![0; delay_start + (delay.len() + 1) * DELAY_DESCRIPTOR];
        for (i, (dll, symbols)) in imports.iter().enumerate() {
            let name = push_str(&mut sec, dll);
            let lookup = push_thunks(&mut sec, pe64, symbols);
            let address = push_thunks(&mut sec, pe64, symbols);
            let d = i * DESCRIPTOR;
            put32(&mut sec, d, rva(lookup)); // OriginalFirstThunk
            put32(&mut sec, d + 12, rva(name));
            put32(&mut sec, d + 16, rva(address)); // FirstThunk
        }
        for (i, (dll, symbols)) in delay.iter().enumerate() {
            let name = push_str(&mut sec, dll);
            let module = push(&mut sec, &[0; 8]);
            let address = push_thunks(&mut sec, pe64, symbols);
            let names = push_thunks(&mut sec, pe64, symbols);
            let d = delay_start + i * DELAY_DESCRIPTOR;
            put32(&mut sec, d, 1); // Attributes: RVA-based
            put32(&mut sec, d + 4, rva(name));
            put32(&mut sec, d + 8, rva(module));
            put32(&mut sec, d + 12, rva(address));
            put32(&mut sec, d + 16, rva(names));
        }
        // The export directory, its arrays and every string: a forward is an address inside
        // the directory's range.
        let export_directory = (!exports.is_empty()).then(|| {
            let n = exports.len();
            let directory = push(&mut sec, &[0; 40]);
            let functions = push(&mut sec, &vec![0; 4 * n]);
            let names = push(&mut sec, &vec![0; 4 * n]);
            let ordinals = push(&mut sec, &vec![0; 2 * n]);
            let dll_name = push_str(&mut sec, "app-local.dll");
            for (i, (name, forward)) in exports.iter().enumerate() {
                let name = push_str(&mut sec, name);
                let address = match forward {
                    Some(target) => rva(push_str(&mut sec, target)),
                    None => SECTION_RVA,
                };
                put32(&mut sec, functions + 4 * i, address);
                put32(&mut sec, names + 4 * i, rva(name));
                put16(&mut sec, ordinals + 2 * i, i as u16);
            }
            put32(&mut sec, directory + 12, rva(dll_name));
            put32(&mut sec, directory + 16, 1); // Base
            put32(&mut sec, directory + 20, n as u32); // NumberOfFunctions
            put32(&mut sec, directory + 24, n as u32); // NumberOfNames
            put32(&mut sec, directory + 28, rva(functions));
            put32(&mut sec, directory + 32, rva(names));
            put32(&mut sec, directory + 36, rva(ordinals));
            (directory, sec.len() - directory)
        });
        sec.resize(sec.len().next_multiple_of(0x200), 0);

        let mut pe = vec![0; SECTION_OFFSET];
        pe[..2].copy_from_slice(b"MZ");
        put32(&mut pe, 0x3c, 0x40); // e_lfanew
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let (machine, characteristics, magic, dirs) = if pe64 {
            (0x8664, 0x0022, 0x20b, 112)
        } else {
            (0x014c, 0x0102, 0x10b, 96)
        };
        let size_of_optional_header = dirs + 16 * 8;
        put16(&mut pe, 0x44, machine);
        put16(&mut pe, 0x46, 1); // NumberOfSections
        put16(&mut pe, 0x54, size_of_optional_header as u16);
        put16(&mut pe, 0x56, characteristics);
        let opt = 0x58;
        put16(&mut pe, opt, magic);
        put32(&mut pe, opt + 32, 0x1000); // SectionAlignment
        put32(&mut pe, opt + 36, 0x200); // FileAlignment
        put32(&mut pe, opt + 56, SECTION_RVA + sec.len() as u32); // SizeOfImage
        put32(&mut pe, opt + 60, SECTION_OFFSET as u32); // SizeOfHeaders
        put32(&mut pe, opt + dirs - 4, 16); // NumberOfRvaAndSizes
        if let Some((directory, size)) = export_directory {
            put32(&mut pe, opt + dirs, rva(directory)); // IMAGE_DIRECTORY_ENTRY_EXPORT
            put32(&mut pe, opt + dirs + 4, size as u32);
        }
        if !imports.is_empty() {
            put32(&mut pe, opt + dirs + 8, rva(0)); // IMAGE_DIRECTORY_ENTRY_IMPORT
            put32(&mut pe, opt + dirs + 12, delay_start as u32);
        }
        if !delay.is_empty() {
            let entry = opt + dirs + 13 * 8; // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            put32(&mut pe, entry, rva(delay_start));
            put32(
                &mut pe,
                entry + 4,
                ((delay.len() + 1) * DELAY_DESCRIPTOR) as u32,
            );
        }
        let section = opt + size_of_optional_header;
        pe[section..section + 6].copy_from_slice(b".idata");
        put32(&mut pe, section + 8, sec.len() as u32); // VirtualSize
        put32(&mut pe, section + 12, SECTION_RVA);
        put32(&mut pe, section + 16, sec.len() as u32); // SizeOfRawData
        put32(&mut pe, section + 20, SECTION_OFFSET as u32); // PointerToRawData
        put32(&mut pe, section + 36, 0xc000_0040); // initialized data, read, write
        pe.extend_from_slice(&sec);
        pe
    }

    fn rva(offset: usize) -> u32 {
        SECTION_RVA + u32::try_from(offset).unwrap()
    }

    fn put16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Appends `bytes` at the next 8-byte boundary and returns their section offset.
    fn push(sec: &mut Vec<u8>, bytes: &[u8]) -> usize {
        sec.resize(sec.len().next_multiple_of(8), 0);
        let offset = sec.len();
        sec.extend_from_slice(bytes);
        offset
    }

    fn push_str(sec: &mut Vec<u8>, s: &str) -> usize {
        push(sec, &[s.as_bytes(), b"\0"].concat())
    }

    /// Appends a null-terminated thunk list (with its hint/name entries) for `symbols`.
    fn push_thunks(sec: &mut Vec<u8>, pe64: bool, symbols: &[&str]) -> usize {
        let (width, ordinal_flag) = if pe64 { (8, 1 << 63) } else { (4, 1 << 31) };
        let mut thunks = Vec::new();
        for symbol in symbols {
            let thunk: u64 = match symbol.strip_prefix('#') {
                Some(ordinal) => ordinal_flag | ordinal.parse::<u64>().unwrap(),
                // Hint 0, then the NUL-terminated name.
                None => rva(push(sec, &[b"\0\0", symbol.as_bytes(), b"\0"].concat())).into(),
            };
            thunks.extend_from_slice(&thunk.to_le_bytes()[..width]);
        }
        thunks.extend_from_slice(&[0; 8][..width]);
        push(sec, &thunks)
    }
}
