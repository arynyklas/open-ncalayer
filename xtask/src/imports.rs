//! PE import gate of the Windows 7 lane (roadmap D14): `cargo xtask check-imports` lists the
//! imports of each executable and fails on DLLs and functions that Windows 7 does not have.

use std::path::Path;

use anyhow::Context as _;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64};
use object::read::pe::{ImageNtHeaders, PeFile};
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

/// One imported function of a PE image, from the regular or the delay-load import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// DLL name as written in the import descriptor.
    pub dll: String,
    /// Function name; `None` for an import by ordinal.
    pub symbol: Option<String>,
}

/// Reads the regular and delay-load imports of a PE32 or PE32+ image.
pub fn read_imports(pe: &[u8]) -> anyhow::Result<Vec<Import>> {
    match FileKind::parse(pe).context("unrecognized file format")? {
        FileKind::Pe32 => imports_of::<ImageNtHeaders32>(pe),
        FileKind::Pe64 => imports_of::<ImageNtHeaders64>(pe),
        kind => anyhow::bail!("not a PE image: {kind:?}"),
    }
}

fn imports_of<Pe: ImageNtHeaders>(pe: &[u8]) -> anyhow::Result<Vec<Import>> {
    let file = PeFile::<Pe>::parse(pe).context("invalid PE image")?;
    file.imports()
        .context("invalid PE import table")?
        .map(|import| {
            let import = import.context("invalid PE import")?;
            Ok(Import {
                dll: String::from_utf8_lossy(import.library()).into_owned(),
                symbol: match import.name() {
                    NameOrOrdinal::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
                    NameOrOrdinal::Ordinal(_) => None,
                },
            })
        })
        .collect()
}

/// Describes every import Windows 7 cannot satisfy, one line per import.
///
/// DLL names compare case-insensitively, function names exactly (PE exports are case-sensitive).
pub fn violations(imports: &[Import]) -> Vec<String> {
    imports
        .iter()
        .filter_map(|import| {
            let missing = if FORBIDDEN_DLLS
                .iter()
                .any(|dll| import.dll.eq_ignore_ascii_case(dll))
                || FORBIDDEN_DLL_PREFIXES.iter().any(|prefix| {
                    import
                        .dll
                        .as_bytes()
                        .get(..prefix.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
                }) {
                "DLL"
            } else if FORBIDDEN_FUNCTIONS.iter().any(|(dll, function)| {
                import.dll.eq_ignore_ascii_case(dll) && import.symbol.as_deref() == Some(*function)
            }) {
                "function"
            } else {
                return None;
            };
            let symbol = import.symbol.as_deref().unwrap_or("<ordinal>");
            Some(format!(
                "{}!{symbol}: {missing} is missing on Windows 7",
                import.dll
            ))
        })
        .collect()
}

/// Prints the violations of each executable to stdout and returns their total count.
pub fn check_imports(exes: &[impl AsRef<Path>]) -> anyhow::Result<usize> {
    let mut total = 0;
    for exe in exes {
        let exe = exe.as_ref();
        let pe = std::fs::read(exe).with_context(|| format!("reading {}", exe.display()))?;
        let imports = read_imports(&pe).with_context(|| format!("parsing {}", exe.display()))?;
        let found = violations(&imports);
        println!(
            "{}: {} forbidden of {} imports",
            exe.display(),
            found.len(),
            imports.len()
        );
        for violation in &found {
            println!("  {violation}");
        }
        total += found.len();
    }
    Ok(total)
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

    #[test]
    fn flags_combase_and_win8_apis() {
        let v = violations(&[
            imp("COMBASE.dll", "CoTaskMemFree"),
            imp("kernel32.dll", "GetSystemTimePreciseAsFileTime"),
            imp("kernel32.dll", "CreateFileW"),
        ]);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn flags_every_forbidden_entry_case_insensitively() {
        let ordinal = Import {
            dll: "combase.DLL".to_owned(),
            symbol: None,
        };
        let v = violations(&[
            ordinal,
            imp("API-MS-WIN-CORE-SYNCH-L1-2-0.dll", "WaitOnAddress"),
            imp("BCryptPrimitives.dll", "ProcessPrng"),
            imp("KERNEL32.DLL", "GetSystemTimePreciseAsFileTime"),
            imp("USER32.dll", "SystemParametersInfoForDpi"),
            imp(
                "api-ms-win-core-winrt-error-l1-1-0.dll",
                "RoOriginateErrorW",
            ),
            imp("API-MS-WIN-CORE-WINRT-L1-1-0.DLL", "RoInitialize"),
        ]);
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
        let v = violations(&[
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
        ]);
        assert!(v.is_empty(), "{v:?}");
    }

    #[cfg(windows)]
    #[test]
    fn reads_own_imports() {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(
            read_imports(&me)
                .unwrap()
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
            );
            let imports = read_imports(&pe).unwrap();
            assert_eq!(
                imports,
                [
                    imp("KERNEL32.dll", "CreateFileW"),
                    imp("KERNEL32.dll", "GetSystemTimePreciseAsFileTime"),
                    Import {
                        dll: "combase.dll".to_owned(),
                        symbol: None,
                    },
                    imp("bcryptprimitives.dll", "ProcessPrng"),
                ],
                "pe64 = {pe64}"
            );
            assert_eq!(violations(&imports).len(), 3, "pe64 = {pe64}");
        }
    }

    #[test]
    fn image_without_imports_is_clean() {
        for pe64 in [false, true] {
            assert!(
                read_imports(&synthetic_pe(pe64, &[], &[]))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn rejects_non_pe_input() {
        assert!(read_imports(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0").is_err());
        assert!(read_imports(b"not an executable").is_err());
        let mut truncated = synthetic_pe(true, &[("kernel32.dll", &["CreateFileW"])], &[]);
        truncated.truncate(0x100);
        assert!(read_imports(&truncated).is_err());
    }

    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = 0x200;

    /// Builds a minimal PE image whose single section holds the import tables. Each entry is
    /// a DLL with its symbols; `#N` imports ordinal `N`.
    fn synthetic_pe(pe64: bool, imports: &[(&str, &[&str])], delay: &[(&str, &[&str])]) -> Vec<u8> {
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
