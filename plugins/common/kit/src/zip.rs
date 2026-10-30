//! Zip archives some sites take from the plugins.
//!
//! The container is written here (local headers, central directory, end record; no data
//! descriptors, no ZIP64), the entries raw-deflated by `flate2`.

use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

/// DOS date of 1980-01-01 (the time is midnight, `0`): every entry's, so the same input
/// gives the same bytes.
const DOS_DATE: u16 = (1 << 5) | 1;
/// Version 2.0: deflate.
const VERSION: u16 = 20;
/// The general-purpose flag of a UTF-8 name.
const UTF8_NAME: u16 = 1 << 11;
/// Compression method 8, deflate.
const DEFLATE: u16 = 8;

/// A zip of `entries` (name, data) in order, each deflated, with a fixed time: the same bytes
/// for the same input. Names that are not ASCII are marked UTF-8.
///
/// # Panics
///
/// If an entry, a name or the archive is 4 GiB or more (no ZIP64), or there are 65 535
/// entries or more.
pub fn deflated(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("in memory");
        let packed = encoder.finish().expect("in memory");
        let flags = if name.is_ascii() { 0 } else { UTF8_NAME };
        let fixed = Fixed {
            flags,
            crc: crc32fast::hash(data),
            packed: u32(packed.len()),
            size: u32(data.len()),
            name_len: u16::try_from(name.len()).expect("a name under 64 KiB"),
        };
        let offset = u32(out.len());

        put32(&mut out, 0x0403_4b50);
        put16(&mut out, VERSION);
        fixed.write(&mut out);
        put16(&mut out, 0); // extra field
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);

        put32(&mut central, 0x0201_4b50);
        put16(&mut central, VERSION); // made by: MS-DOS, 2.0
        put16(&mut central, VERSION);
        fixed.write(&mut central);
        put16(&mut central, 0); // extra field
        put16(&mut central, 0); // comment
        put16(&mut central, 0); // disk
        put16(&mut central, 0); // internal attributes
        put32(&mut central, 0); // external attributes
        put32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let count = u16::try_from(entries.len()).expect("under 65 535 entries");
    let central_offset = u32(out.len());
    let central_len = u32(central.len());
    out.extend_from_slice(&central);
    put32(&mut out, 0x0605_4b50);
    put16(&mut out, 0); // this disk
    put16(&mut out, 0); // the central directory's disk
    put16(&mut out, count);
    put16(&mut out, count);
    put32(&mut out, central_len);
    put32(&mut out, central_offset);
    put16(&mut out, 0); // comment
    out
}

/// The fields a local header and its central directory entry share, from the flags to the
/// name's length.
struct Fixed {
    flags: u16,
    crc: u32,
    packed: u32,
    size: u32,
    name_len: u16,
}

impl Fixed {
    fn write(&self, out: &mut Vec<u8>) {
        put16(out, self.flags);
        put16(out, DEFLATE);
        put16(out, 0); // time: midnight
        put16(out, DOS_DATE);
        put32(out, self.crc);
        put32(out, self.packed);
        put32(out, self.size);
        put16(out, self.name_len);
    }
}

fn u32(len: usize) -> u32 {
    u32::try_from(len).expect("under 4 GiB")
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    #[test]
    fn entries_in_order_and_deterministic() {
        let entries: [(&str, &[u8]); 3] = [
            ("file_1", b"one"),
            ("map.xml", b"<x/>"),
            ("документ.pdf", &[0u8; 5000]),
        ];
        let a = super::deflated(&entries);
        assert_eq!(a, super::deflated(&entries));
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(a)).unwrap();
        assert_eq!(archive.len(), 3);
        assert_eq!(archive.by_index(0).unwrap().name().unwrap(), "file_1");
        let mut text = String::new();
        archive
            .by_name("map.xml")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "<x/>");
        let mut file = archive.by_index(2).unwrap();
        assert_eq!(file.name().unwrap(), "документ.pdf");
        assert_eq!(file.compression(), zip::CompressionMethod::Deflated);
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        assert_eq!(data, [0u8; 5000]);
    }

    #[test]
    fn empty_archive_is_the_end_record() {
        assert_eq!(
            super::deflated(&[]),
            [
                0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
