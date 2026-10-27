//! Shell Link files (`.lnk`, \[MS-SHLLINK\]): the target paths a shortcut holds, read
//! without the shell and within bounds.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Whether the shortcut `path` points to a file named `file_name` (ASCII, compared without
/// case). A file larger than `max` bytes is not a shortcut of ours: `false`.
///
/// # Errors
///
/// The file cannot be read.
pub(crate) fn points_to(path: &Path, file_name: &str, max: u64) -> io::Result<bool> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Ok(false);
    }
    Ok(shortcut_targets(&bytes).iter().any(|target| {
        target
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(file_name))
    }))
}

/// The target paths a Shell Link (`.lnk`, \[MS-SHLLINK\]) holds: the local path of its
/// LinkInfo (ANSI and Unicode) and its relative path. Empty if it is not a shortcut.
fn shortcut_targets(bytes: &[u8]) -> Vec<String> {
    /// `{00021401-0000-0000-C000-000000000046}` as stored.
    const CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    const HEADER: usize = 0x4C;
    const HAS_ID_LIST: u32 = 0x1;
    const HAS_LINK_INFO: u32 = 0x2;
    const HAS_NAME: u32 = 0x4;
    const HAS_RELATIVE_PATH: u32 = 0x8;
    const IS_UNICODE: u32 = 0x80;
    const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;

    let mut targets = Vec::new();
    if u32_at(bytes, 0) != Some(HEADER as u32) || bytes.get(4..20) != Some(&CLSID[..]) {
        return targets;
    }
    let Some(flags) = u32_at(bytes, 0x14) else {
        return targets;
    };
    let mut at = HEADER;
    if flags & HAS_ID_LIST != 0 {
        let Some(size) = u16_at(bytes, at) else {
            return targets;
        };
        at = at.saturating_add(2 + usize::from(size));
    }
    if flags & HAS_LINK_INFO != 0 {
        let Some(info) = bytes.get(at..) else {
            return targets;
        };
        let field = |offset: usize| u32_at(info, offset).map(|v| v as usize);
        let (Some(size), Some(header), Some(info_flags)) = (field(0), field(4), field(8)) else {
            return targets;
        };
        if info_flags & (VOLUME_ID_AND_LOCAL_BASE_PATH as usize) != 0 {
            let suffix = field(24).and_then(|o| ansi_at(info, o)).unwrap_or_default();
            if let Some(base) = field(16).and_then(|o| ansi_at(info, o)) {
                targets.push(base + &suffix);
            }
            if header >= 0x24 {
                let suffix = field(32)
                    .and_then(|o| utf16_at(info, o))
                    .unwrap_or_default();
                if let Some(base) = field(28).and_then(|o| utf16_at(info, o)) {
                    targets.push(base + &suffix);
                }
            }
        }
        at = at.saturating_add(size);
    }
    // StringData: the name first, then the relative path.
    let unicode = flags & IS_UNICODE != 0;
    let string = |at: &mut usize| -> Option<String> {
        let count = usize::from(u16_at(bytes, *at)?);
        let start = at.saturating_add(2);
        let len = if unicode { count * 2 } else { count };
        let raw = bytes.get(start..start.saturating_add(len))?;
        *at = start + len;
        Some(if unicode {
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            raw.iter().map(|&b| char::from(b)).collect()
        })
    };
    if flags & HAS_NAME != 0 && string(&mut at).is_none() {
        return targets;
    }
    if flags & HAS_RELATIVE_PATH != 0
        && let Some(relative) = string(&mut at)
    {
        targets.push(relative);
    }
    targets
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The NUL-terminated single-byte string at `at`, its bytes taken as Latin-1 (the name
/// compared is ASCII).
fn ansi_at(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some(rest[..end].iter().map(|&b| char::from(b)).collect())
}

/// The NUL-terminated UTF-16LE string at `at`.
fn utf16_at(bytes: &[u8], at: usize) -> Option<String> {
    let mut units = Vec::new();
    for &c in bytes.get(at..)?.as_chunks::<2>().0 {
        match u16::from_le_bytes(c) {
            0 => return Some(String::from_utf16_lossy(&units)),
            u => units.push(u),
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    /// A Shell Link to `target` the way the shell writes one for a local file: a LinkInfo
    /// with the local path (ANSI, and Unicode if `unicode`), and the relative path.
    pub(crate) fn shortcut(target: &str, unicode: bool) -> Vec<u8> {
        let mut info_header = Vec::new();
        let header_size: u32 = if unicode { 0x24 } else { 0x1C };
        let volume = {
            let mut v = Vec::new();
            v.extend(0x11u32.to_le_bytes()); // VolumeIDSize
            v.extend(3u32.to_le_bytes()); // DRIVE_FIXED
            v.extend(0u32.to_le_bytes()); // serial
            v.extend(0x10u32.to_le_bytes()); // label offset
            v.push(0); // empty label
            v
        };
        let ansi: Vec<u8> = target
            .bytes()
            .map(|b| if b.is_ascii() { b } else { b'?' })
            .chain([0])
            .collect();
        let wide: Vec<u8> = target
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let volume_at = header_size;
        let base_at = volume_at + volume.len() as u32;
        let suffix_at = base_at + ansi.len() as u32;
        let base_w_at = suffix_at + 1;
        let suffix_w_at = base_w_at + wide.len() as u32;
        let mut body = volume.clone();
        body.extend(&ansi);
        body.push(0); // empty common path suffix
        if unicode {
            body.extend(&wide);
            body.extend([0, 0]);
        }
        let size = header_size + body.len() as u32;
        for v in [size, header_size, 1, volume_at, base_at, 0, suffix_at] {
            info_header.extend(v.to_le_bytes());
        }
        if unicode {
            info_header.extend(base_w_at.to_le_bytes());
            info_header.extend(suffix_w_at.to_le_bytes());
        }
        let mut lnk = Vec::new();
        lnk.extend(0x4Cu32.to_le_bytes());
        lnk.extend([
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        // HasLinkTargetIDList | HasLinkInfo | HasRelativePath | IsUnicode
        lnk.extend((0x1u32 | 0x2 | 0x8 | 0x80).to_le_bytes());
        lnk.resize(0x4C, 0);
        // An ID list of one empty item list (only its terminator).
        lnk.extend(2u16.to_le_bytes());
        lnk.extend([0, 0]);
        lnk.extend(info_header);
        lnk.extend(body);
        let relative: Vec<u16> = format!("..\\{target}").encode_utf16().collect();
        lnk.extend((relative.len() as u16).to_le_bytes());
        lnk.extend(relative.into_iter().flat_map(u16::to_le_bytes));
        lnk.extend(0u32.to_le_bytes()); // TerminalBlock
        lnk
    }

    #[test]
    fn shortcut_targets_are_read() {
        let target = r"C:\Program Files\NCALayer\NCALayer.exe";
        assert_eq!(
            shortcut_targets(&shortcut(target, false)),
            [target.to_owned(), format!("..\\{target}")]
        );
        let target = r"C:\Users\Әлия\AppData\Roaming\NCALayer\NCALayer.exe";
        let targets = shortcut_targets(&shortcut(target, true));
        assert_eq!(targets[1], target);
        // Not a shortcut, or cut short: nothing, without a panic.
        assert!(shortcut_targets(b"[Desktop Entry]\n").is_empty());
        let whole = shortcut(target, true);
        for len in 0..whole.len() {
            let _ = shortcut_targets(&whole[..len]);
        }
    }

    #[test]
    fn only_shortcuts_within_the_bound_are_read() {
        let d = tempfile::tempdir().unwrap();
        let lnk = d.path().join("a.lnk");
        let bytes = shortcut(r"C:\NCALayer\NCALayer.exe", true);
        fs::write(&lnk, &bytes).unwrap();
        let len = bytes.len() as u64;
        assert!(points_to(&lnk, "ncalayer.exe", len).unwrap());
        assert!(!points_to(&lnk, "other.exe", len).unwrap());
        assert!(!points_to(&lnk, "NCALayer.exe", len - 1).unwrap());
        assert!(points_to(&d.path().join("missing.lnk"), "NCALayer.exe", len).is_err());
    }

    /// The real shell's shortcut to a file of the sandbox. `WScript.Shell` saves under ANSI
    /// paths only, so the sandbox is under `target/` (not a `%TEMP%` that may hold the
    /// user's Cyrillic name); the localized shortcut name is covered by the synthetic ones.
    #[cfg(windows)]
    #[test]
    fn shell_shortcut_target_is_read() {
        let exe = std::env::current_exe().unwrap();
        let d = tempfile::Builder::new()
            .prefix("oncl-lnk-")
            .tempdir_in(exe.parent().unwrap())
            .unwrap();
        if !d.path().to_string_lossy().is_ascii() {
            eprintln!("skipped: {} is not ASCII", d.path().display());
            return;
        }
        let target = d.path().join("NCALayer").join("NCALayer.exe");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"MZ").unwrap();
        let lnk = d.path().join("Startup item.lnk");
        let script = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.Save()",
            lnk.display(),
            target.display()
        );
        let status = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            points_to(&lnk, "NCALayer.exe", 1 << 20).unwrap(),
            "{:?}",
            shortcut_targets(&fs::read(&lnk).unwrap())
        );
    }
}
