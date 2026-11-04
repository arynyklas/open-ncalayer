//! The Velopack `Setup.exe` an installer entry carries, and what it says about it.
//!
//! The release makes the entry from the installer's own program (a PE image built without a
//! payload) and the unchanged `Setup.exe` vpk made: [`append`] writes the payload right after
//! the last section of the image, followed by its version and a footer with the payload's
//! length, architecture and SHA-256. Authenticode then signs the whole file, so the payload
//! is covered by the signature, and the entry reads it from its own image ([`read`]): the
//! footer is looked for before the signature's certificate table, the payload must begin
//! right after the last section (nothing else hides in the image), nothing may follow the
//! certificate table, and the payload must be a PE of the footer's architecture with the
//! SHA-256 the footer names.

use std::fmt;
use std::ops::Range;

use semver::Version;
use sha2::{Digest, Sha256};

/// Ends the footer: what [`read`] looks for.
const MAGIC: &[u8; 8] = b"ONCLWGP1";
/// `payload length: u64`, `version length: u32`, `architecture: u32`, SHA-256, [`MAGIC`].
const FOOTER: usize = 8 + 4 + 4 + 32 + MAGIC.len();
/// The longest version text a footer may carry.
const MAX_VERSION: usize = 128;
/// A certificate table is aligned to 8 bytes: up to 7 zero bytes may lie between the footer
/// and it.
const PADDING: usize = 7;

/// The architecture of a Windows flavor: the entry, its payload and the installed program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    /// `x64` of the manifest, `win-x64`.
    X64,
    /// `x86` of the manifest, `win-x86`.
    X86,
}

impl Arch {
    /// The architecture this program was built for, if it is one of the flavors.
    pub const fn this() -> Option<Arch> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X64)
        } else if cfg!(target_arch = "x86") {
            Some(Arch::X86)
        } else {
            None
        }
    }

    /// `machineArchitecture` of the package manifest.
    pub const fn manifest_name(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
        }
    }

    /// `IMAGE_FILE_HEADER.Machine` of a PE of this architecture.
    const fn machine(self) -> u16 {
        match self {
            Arch::X64 => 0x8664,
            Arch::X86 => 0x014c,
        }
    }

    fn code(self) -> u32 {
        match self {
            Arch::X64 => 1,
            Arch::X86 => 2,
        }
    }

    fn from_code(code: u32) -> Option<Arch> {
        match code {
            1 => Some(Arch::X64),
            2 => Some(Arch::X86),
            _ => None,
        }
    }

    /// The architecture of the PE image `pe`.
    pub fn of_image(pe: &[u8]) -> Option<Arch> {
        let machine = Layout::of(pe)?.machine;
        [Arch::X64, Arch::X86]
            .into_iter()
            .find(|arch| arch.machine() == machine)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.manifest_name())
    }
}

/// Why an image has no payload to trust.
#[derive(Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// The image is not a PE this module can read.
    NotAnImage,
    /// The image carries no payload (a build made without one).
    NoPayload,
    /// The footer, the sizes or what surrounds the payload are not what [`append`] writes.
    Malformed(&'static str),
    /// The payload is not the one the footer names.
    HashMismatch,
    /// The version in the footer is not a version.
    BadVersion,
    /// The payload is a PE of another architecture than the footer names, or is no PE.
    PayloadArch,
    /// [`append`] only takes an image without a payload and without a signature.
    NotWritable(&'static str),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::NotAnImage => f.write_str("the installer is not a readable PE image"),
            PayloadError::NoPayload => f.write_str("the installer carries no Setup payload"),
            PayloadError::Malformed(why) => write!(f, "the Setup payload is damaged: {why}"),
            PayloadError::HashMismatch => f.write_str(
                "the Setup payload does not match its SHA-256: the installer is damaged",
            ),
            PayloadError::BadVersion => f.write_str("the Setup payload names no valid version"),
            PayloadError::PayloadArch => {
                f.write_str("the Setup payload is not a program of the architecture it names")
            }
            PayloadError::NotWritable(why) => write!(f, "cannot write the payload: {why}"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// The payload of an image, checked.
#[derive(Debug)]
pub struct Embedded<'a> {
    /// The version of the program the payload installs.
    pub version: Version,
    /// The architecture of the payload and the program.
    pub arch: Arch,
    /// The SHA-256 of [`Embedded::setup`].
    pub sha256: [u8; 32],
    /// The unchanged `Setup.exe`.
    pub setup: &'a [u8],
}

/// What the headers of a PE image say about where its file ends and a signature begins.
struct Layout {
    machine: u16,
    /// The file offset after the last section's raw data (and the headers).
    sections_end: usize,
    /// The certificate table: file offset and size.
    certificates: Option<(usize, usize)>,
}

impl Layout {
    fn of(pe: &[u8]) -> Option<Layout> {
        let u16_at = |at: usize| Some(u16::from_le_bytes(pe.get(at..at + 2)?.try_into().ok()?));
        let u32_at = |at: usize| Some(u32::from_le_bytes(pe.get(at..at + 4)?.try_into().ok()?));
        if pe.get(..2)? != b"MZ" {
            return None;
        }
        let pe_at = usize::try_from(u32_at(0x3c)?).ok()?;
        if pe.get(pe_at..pe_at + 4)? != b"PE\0\0" {
            return None;
        }
        let coff = pe_at + 4;
        let machine = u16_at(coff)?;
        let sections = usize::from(u16_at(coff + 2)?);
        let optional_size = usize::from(u16_at(coff + 16)?);
        let optional = coff + 20;
        let (headers_at, directories_at) = match u16_at(optional)? {
            0x10b => (optional + 60, optional + 96),
            0x20b => (optional + 60, optional + 112),
            _ => return None,
        };
        let mut sections_end = usize::try_from(u32_at(headers_at)?).ok()?;
        let table = optional + optional_size;
        for index in 0..sections {
            let at = table + index * 40;
            let size = usize::try_from(u32_at(at + 16)?).ok()?;
            let pointer = usize::try_from(u32_at(at + 20)?).ok()?;
            if size != 0 {
                sections_end = sections_end.max(pointer.checked_add(size)?);
            }
        }
        // Data directory 4, the certificate table: its "address" is a file offset.
        let certificates = if u32_at(directories_at - 4)? > 4 {
            let entry = directories_at + 4 * 8;
            let offset = usize::try_from(u32_at(entry)?).ok()?;
            let size = usize::try_from(u32_at(entry + 4)?).ok()?;
            (offset != 0 && size != 0).then_some((offset, size))
        } else {
            None
        };
        Some(Layout {
            machine,
            sections_end,
            certificates,
        })
    }
}

/// `image` (an unsigned PE without a payload) with `setup` appended: the payload, the
/// `version` of the program it installs and the footer naming `setup`'s length, `arch` and
/// SHA-256.
///
/// # Errors
///
/// `image` is no PE, already carries something after its last section (a payload or a
/// signature), or `setup` is not a PE of `arch`.
pub fn append(
    image: &[u8],
    setup: &[u8],
    version: &Version,
    arch: Arch,
) -> Result<Vec<u8>, PayloadError> {
    let layout = Layout::of(image).ok_or(PayloadError::NotAnImage)?;
    if layout.certificates.is_some() {
        return Err(PayloadError::NotWritable("the image is signed already"));
    }
    if layout.sections_end != image.len() {
        return Err(PayloadError::NotWritable(
            "the image has data after its sections",
        ));
    }
    if Arch::of_image(image) != Some(arch) {
        return Err(PayloadError::NotWritable(
            "the image is not of the payload's architecture",
        ));
    }
    if Arch::of_image(setup) != Some(arch) {
        return Err(PayloadError::PayloadArch);
    }
    let version_text = version.to_string();
    if version_text.len() > MAX_VERSION {
        return Err(PayloadError::BadVersion);
    }
    let mut out = Vec::with_capacity(image.len() + setup.len() + version_text.len() + FOOTER);
    out.extend_from_slice(image);
    out.extend_from_slice(setup);
    out.extend_from_slice(version_text.as_bytes());
    out.extend_from_slice(&(setup.len() as u64).to_le_bytes());
    out.extend_from_slice(&(version_text.len() as u32).to_le_bytes());
    out.extend_from_slice(&arch.code().to_le_bytes());
    out.extend_from_slice(&Sha256::digest(setup));
    out.extend_from_slice(MAGIC);
    Ok(out)
}

/// The payload of `image` (the file of the installer entry, signed or not), after checking
/// its footer, its place in the image, its SHA-256 and its architecture.
///
/// # Errors
///
/// See [`PayloadError`].
pub fn read(image: &[u8]) -> Result<Embedded<'_>, PayloadError> {
    let layout = Layout::of(image).ok_or(PayloadError::NotAnImage)?;
    let end = match layout.certificates {
        Some((offset, size)) => {
            // The signature is the last thing in the file: what follows it is not covered.
            if offset.checked_add(size) != Some(image.len()) {
                return Err(PayloadError::Malformed("data after the signature"));
            }
            offset
        }
        None => image.len(),
    };
    let body = image.get(..end).ok_or(PayloadError::NotAnImage)?;
    // Nothing (or the alignment padding of a signature) after the last section.
    if body.len() >= layout.sections_end
        && body.len() - layout.sections_end <= PADDING
        && body[layout.sections_end..].iter().all(|b| *b == 0)
    {
        return Err(PayloadError::NoPayload);
    }
    let padding = body
        .iter()
        .rev()
        .take(PADDING)
        .take_while(|b| **b == 0)
        .count();
    let body = &body[..body.len() - padding];
    if body.len() < layout.sections_end + FOOTER || !body.ends_with(MAGIC) {
        return Err(PayloadError::Malformed("no footer"));
    }
    let footer = &body[body.len() - FOOTER..];
    let payload_len = u64::from_le_bytes(footer[..8].try_into().expect("8 bytes"));
    let version_len = u32::from_le_bytes(footer[8..12].try_into().expect("4 bytes"));
    let arch = u32::from_le_bytes(footer[12..16].try_into().expect("4 bytes"));
    let sha256: [u8; 32] = footer[16..48].try_into().expect("32 bytes");

    let (payload_len, version_len) = (
        usize::try_from(payload_len).map_err(|_| PayloadError::Malformed("size"))?,
        usize::try_from(version_len).map_err(|_| PayloadError::Malformed("size"))?,
    );
    if version_len == 0 || version_len > MAX_VERSION {
        return Err(PayloadError::BadVersion);
    }
    let setup_at = (body.len() - FOOTER)
        .checked_sub(version_len)
        .and_then(|at| at.checked_sub(payload_len))
        .ok_or(PayloadError::Malformed("sizes"))?;
    if setup_at != layout.sections_end {
        return Err(PayloadError::Malformed(
            "the payload does not begin where the image's sections end",
        ));
    }
    let setup = &body[setup_at..setup_at + payload_len];
    let version_text = std::str::from_utf8(&body[setup_at + payload_len..body.len() - FOOTER])
        .map_err(|_| PayloadError::BadVersion)?;
    let version = Version::parse(version_text).map_err(|_| PayloadError::BadVersion)?;
    let arch = Arch::from_code(arch).ok_or(PayloadError::Malformed("architecture"))?;
    if Sha256::digest(setup).as_slice() != sha256 {
        return Err(PayloadError::HashMismatch);
    }
    if Arch::of_image(setup) != Some(arch) {
        return Err(PayloadError::PayloadArch);
    }
    Ok(Embedded {
        version,
        arch,
        sha256,
        setup,
    })
}

/// The file offsets of the payload in `image`, for tools that write it elsewhere.
///
/// # Errors
///
/// As [`read`].
pub fn setup_range(image: &[u8]) -> Result<Range<usize>, PayloadError> {
    let embedded = read(image)?;
    let start = embedded.setup.as_ptr() as usize - image.as_ptr() as usize;
    Ok(start..start + embedded.setup.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE image: one section of `section` bytes, `arch`, optionally with a certificate
    /// table of `certificates` bytes at the end of the file.
    pub(crate) fn pe(arch: Arch, section: &[u8], certificates: Option<usize>) -> Vec<u8> {
        let pe_at = 0x80usize;
        let optional_size = 0xf0usize;
        let headers = 0x200usize;
        let mut image = vec![0u8; headers];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_at as u32).to_le_bytes());
        image[pe_at..pe_at + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_at + 4;
        image[coff..coff + 2].copy_from_slice(&arch.machine().to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        let optional = coff + 20;
        // PE32+ layout for both: the reader only needs the fields it reads.
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&(headers as u32).to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let table = optional + optional_size;
        image[table + 16..table + 20].copy_from_slice(&(section.len() as u32).to_le_bytes());
        image[table + 20..table + 24].copy_from_slice(&(headers as u32).to_le_bytes());
        image.extend_from_slice(section);
        if let Some(size) = certificates {
            // The table is aligned to 8 bytes.
            while !image.len().is_multiple_of(8) {
                image.push(0);
            }
            let offset = image.len() as u32;
            let entry = optional + 112 + 4 * 8;
            image[entry..entry + 4].copy_from_slice(&offset.to_le_bytes());
            image[entry + 4..entry + 8].copy_from_slice(&(size as u32).to_le_bytes());
            image.extend(std::iter::repeat_n(0xAB, size));
        }
        image
    }

    fn version() -> Version {
        Version::parse("0.1.0-alpha.8").unwrap()
    }

    fn entry(arch: Arch) -> (Vec<u8>, Vec<u8>) {
        let image = pe(arch, &[1; 100], None);
        let setup = pe(arch, &[7; 3000], None);
        (image, setup)
    }

    #[test]
    fn what_is_appended_is_read_back_checked() {
        let (image, setup) = entry(Arch::X64);
        let entry = append(&image, &setup, &version(), Arch::X64).unwrap();
        let read = read(&entry).unwrap();
        assert_eq!(read.setup, setup);
        assert_eq!(read.version, version());
        assert_eq!(read.arch, Arch::X64);
        assert_eq!(read.sha256.as_slice(), Sha256::digest(&setup).as_slice());
        assert_eq!(setup_range(&entry).unwrap().len(), setup.len());
    }

    #[test]
    fn an_image_without_a_payload_says_so() {
        let (image, _) = entry(Arch::X64);
        assert_eq!(read(&image).unwrap_err(), PayloadError::NoPayload);
        assert_eq!(read(b"not a pe").unwrap_err(), PayloadError::NotAnImage);
    }

    #[test]
    fn a_changed_byte_of_the_payload_is_a_hash_mismatch() {
        let (image, setup) = entry(Arch::X64);
        let mut entry = append(&image, &setup, &version(), Arch::X64).unwrap();
        let at = setup_range(&entry).unwrap().start + 1500;
        entry[at] ^= 1;
        assert_eq!(read(&entry).unwrap_err(), PayloadError::HashMismatch);
    }

    #[test]
    fn the_footer_cannot_be_made_to_name_other_sizes_or_places() {
        let (image, setup) = entry(Arch::X64);
        let entry = append(&image, &setup, &version(), Arch::X64).unwrap();
        // Data in front of the payload, between the sections and it, is refused.
        let mut gap = image.clone();
        gap.extend_from_slice(b"smuggled");
        let hidden = {
            let mut e = gap;
            e.extend_from_slice(&entry[image.len()..]);
            e
        };
        assert!(matches!(
            read(&hidden).unwrap_err(),
            PayloadError::Malformed(_)
        ));
        // A payload length larger than the image.
        let mut long = entry.clone();
        let footer = long.len() - FOOTER;
        long[footer..footer + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            read(&long).unwrap_err(),
            PayloadError::Malformed(_)
        ));
        // A version that is not one, and one that is too long.
        let mut bad = entry.clone();
        let at = bad.len() - FOOTER - 1;
        bad[at] = b'!';
        assert_eq!(read(&bad).unwrap_err(), PayloadError::BadVersion);
        let mut huge = entry;
        let footer = huge.len() - FOOTER;
        huge[footer + 8..footer + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(read(&huge).unwrap_err(), PayloadError::BadVersion);
    }

    #[test]
    fn the_payload_must_be_of_the_architecture_the_footer_names() {
        let (image, _) = entry(Arch::X64);
        let x86_setup = pe(Arch::X86, &[7; 300], None);
        assert_eq!(
            append(&image, &x86_setup, &version(), Arch::X64).unwrap_err(),
            PayloadError::PayloadArch
        );
        assert!(matches!(
            append(&image, &x86_setup, &version(), Arch::X86).unwrap_err(),
            PayloadError::NotWritable(_)
        ));
        // A footer rewritten to say x86 over an x64 payload is refused too.
        let x64_setup = pe(Arch::X64, &[7; 300], None);
        let mut entry = append(&image, &x64_setup, &version(), Arch::X64).unwrap();
        let footer = entry.len() - FOOTER;
        entry[footer + 12..footer + 16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(read(&entry).unwrap_err(), PayloadError::PayloadArch);
        // A payload that is no PE at all.
        assert_eq!(
            append(&image, b"MZ nonsense", &version(), Arch::X64).unwrap_err(),
            PayloadError::PayloadArch
        );
    }

    #[test]
    fn a_signature_after_the_payload_does_not_hide_it_and_data_after_it_is_refused() {
        let (image, setup) = entry(Arch::X64);
        let appended = append(&image, &setup, &version(), Arch::X64).unwrap();
        // Authenticode puts its certificate table after the (8-aligned) end of the image.
        let signed = {
            let mut base = appended.clone();
            // `pe()` only places a table in what it builds: place one by hand.
            while !base.len().is_multiple_of(8) {
                base.push(0);
            }
            let offset = base.len();
            base.extend(std::iter::repeat_n(0xCD, 64));
            let entry_at = 0x80 + 4 + 20 + 112 + 4 * 8;
            base[entry_at..entry_at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
            base[entry_at + 4..entry_at + 8].copy_from_slice(&64u32.to_le_bytes());
            base
        };
        let read_back = read(&signed).unwrap();
        assert_eq!(read_back.setup, setup);
        // The signature is not the last thing in the file: not covered, refused.
        let mut trailing = signed;
        trailing.extend_from_slice(b"unsigned tail");
        assert!(matches!(
            read(&trailing).unwrap_err(),
            PayloadError::Malformed(_)
        ));
    }

    #[test]
    fn a_signed_or_already_loaded_image_takes_no_payload() {
        let (image, setup) = entry(Arch::X64);
        let signed = pe(Arch::X64, &[1; 100], Some(32));
        assert!(matches!(
            append(&signed, &setup, &version(), Arch::X64).unwrap_err(),
            PayloadError::NotWritable(_)
        ));
        let loaded = append(&image, &setup, &version(), Arch::X64).unwrap();
        assert!(matches!(
            append(&loaded, &setup, &version(), Arch::X64).unwrap_err(),
            PayloadError::NotWritable(_)
        ));
    }
}
