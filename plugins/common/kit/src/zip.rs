//! Zip archives some sites take from the plugins.

use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

/// A zip of `entries` (name, data) in order, each deflated, with a fixed time: the same bytes
/// for the same input.
///
/// # Panics
///
/// Never: the archive is written in memory.
pub fn deflated(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    for (name, data) in entries {
        zip.start_file(*name, options).expect("in memory");
        zip.write_all(data).expect("in memory");
    }
    zip.finish().expect("in memory").into_inner()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    #[test]
    fn entries_in_order_and_deterministic() {
        let entries: [(&str, &[u8]); 2] = [("file_1", b"one"), ("map.xml", b"<x/>")];
        let a = super::deflated(&entries);
        assert_eq!(a, super::deflated(&entries));
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(a)).unwrap();
        assert_eq!(archive.by_index(0).unwrap().name().unwrap(), "file_1");
        let mut text = String::new();
        archive
            .by_name("map.xml")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "<x/>");
    }
}
