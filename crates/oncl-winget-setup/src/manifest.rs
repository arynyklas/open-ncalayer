//! The application manifest (`RT_MANIFEST` resource) of a PE image.
//!
//! The installer entry must carry one that says `asInvoker`: without a manifest Windows
//! guesses from the file name ("setup") that the program is a legacy installer and shows a
//! UAC prompt before the entry can start, then the entry (rightly) refuses the elevated
//! token it got. [`of`] reads the resource the loader reads; the release gate and the tests
//! use it.

/// `RT_MANIFEST`.
const RT_MANIFEST: u32 = 24;

/// The text of the first manifest resource of the PE `image`, if it has one.
pub fn of(image: &[u8]) -> Option<String> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(image.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?));
    let pe_at = usize::try_from(u32_at(0x3c)?).ok()?;
    if image.get(..2)? != b"MZ" || image.get(pe_at..pe_at + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_at + 4;
    let sections = usize::from(u16_at(coff + 2)?);
    let optional_size = usize::from(u16_at(coff + 16)?);
    let optional = coff + 20;
    let directories_at = match u16_at(optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    // Data directory 2: the resource table.
    if u32_at(directories_at - 4)? <= 2 {
        return None;
    }
    let root_rva = u32_at(directories_at + 2 * 8)?;
    if root_rva == 0 {
        return None;
    }
    let table = optional + optional_size;
    let to_file = |rva: u32| -> Option<usize> {
        (0..sections).find_map(|index| {
            let at = table + index * 40;
            let virtual_size = u32_at(at + 8)?;
            let section_rva = u32_at(at + 12)?;
            let raw_size = u32_at(at + 16)?;
            let raw_at = u32_at(at + 20)?;
            let extent = virtual_size.max(raw_size);
            let inside = rva.checked_sub(section_rva).filter(|d| *d < extent)?;
            usize::try_from(raw_at.checked_add(inside)?).ok()
        })
    };
    let root = to_file(root_rva)?;
    // One level of the resource tree: the offset (from `root`) of the entry with `id`
    // (`None`: the first entry), and whether it is a subdirectory.
    let entry = |dir: usize, id: Option<u32>| -> Option<(usize, bool)> {
        let named = usize::from(u16_at(dir + 12)?);
        let ids = usize::from(u16_at(dir + 14)?);
        (named..named + ids).find_map(|index| {
            let at = dir + 16 + index * 8;
            if id.is_some_and(|want| u32_at(at) != Some(want)) {
                return None;
            }
            let target = u32_at(at + 4)?;
            Some((
                root + usize::try_from(target & 0x7fff_ffff).ok()?,
                target >> 31 == 1,
            ))
        })
    };
    let (by_name, sub) = entry(root, Some(RT_MANIFEST))?;
    if !sub {
        return None;
    }
    let (by_language, sub) = entry(by_name, None)?;
    if !sub {
        return None;
    }
    let (data, sub) = entry(by_language, None)?;
    if sub {
        return None;
    }
    let start = to_file(u32_at(data)?)?;
    let size = usize::try_from(u32_at(data + 4)?).ok()?;
    let bytes = image.get(start..start.checked_add(size)?)?;
    String::from_utf8(
        bytes
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(bytes)
            .to_vec(),
    )
    .ok()
}

/// Whether the PE `image` carries a manifest that asks for no elevation (`asInvoker`).
pub fn is_as_invoker(image: &[u8]) -> bool {
    of(image).is_some_and(|text| text.contains("level=\"asInvoker\""))
}
