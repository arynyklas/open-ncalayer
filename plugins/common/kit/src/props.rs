//! `java.util.Properties.storeToXML(out, comment)` of Java 8, as plugins sent it to servers.
//!
//! The text: the XML declaration (`standalone="no"`), the properties DTD, `<properties>`, the
//! comment if not empty, one `<entry key="…">value</entry>` per property and `</properties>`,
//! each on a line of its own ended by the platform's line separator. The entries come in the
//! order of `stringPropertyNames()`: the properties copied into a new `Hashtable`, iterated.
//! That order is emulated ([`hashtable_order`]) and not yet checked against a capture of the
//! original.

/// `Properties.storeToXML` of `entries` (put in this order) with `comment`, lines ended by
/// `line_separator` (`\r\n` on Windows, `\n` elsewhere).
pub fn store_to_xml(comment: &str, entries: &[(&str, &str)], line_separator: &str) -> String {
    let nl = line_separator;
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>{nl}\
         <!DOCTYPE properties SYSTEM \"http://java.sun.com/dtd/properties.dtd\">{nl}\
         <properties>{nl}"
    );
    if !comment.is_empty() {
        out.push_str(&format!(
            "<comment>{}</comment>{nl}",
            escape(comment, false)
        ));
    }
    let keys: Vec<&str> = entries.iter().map(|(k, _)| *k).collect();
    // `stringPropertyNames()`: the properties' own iteration order, copied into a new table.
    let own = hashtable_order(&keys);
    let copied: Vec<&str> = own.iter().map(|&i| keys[i]).collect();
    for i in hashtable_order(&copied) {
        let key = copied[i];
        let value = entries
            .iter()
            .find(|(k, _)| *k == key)
            .map_or("", |(_, v)| v);
        out.push_str(&format!(
            "<entry key=\"{}\">{}</entry>{nl}",
            escape(key, true),
            escape(value, false)
        ));
    }
    out.push_str(&format!("</properties>{nl}"));
    out
}

/// XML text: `&`, `<`, `>` escaped, and `"` in an attribute.
fn escape(s: &str, attribute: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// The iteration order of a `java.util.Hashtable` (11 buckets, rehashed to `2n + 1` when
/// the count reaches three quarters) into which the distinct `keys` were put in order: their
/// indices. Buckets are walked from the last to the first, each from its newest entry.
pub fn hashtable_order(keys: &[&str]) -> Vec<usize> {
    let hash = |k: &str| oncl_pdk::javamap::string_hash(k);
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); 11];
    let index = |h: i32, len: usize| ((h & 0x7fff_ffff) as usize) % len;
    for (i, key) in keys.iter().enumerate() {
        // `count` is the number of entries before this one.
        let count = i;
        let threshold = buckets.len() * 3 / 4;
        if count >= threshold {
            // `rehash()`: old buckets from the last, each chain from its head, each entry put
            // at the head of its new bucket.
            let len = buckets.len() * 2 + 1;
            let mut grown: Vec<Vec<usize>> = vec![Vec::new(); len];
            for chain in buckets.iter().rev() {
                for &e in chain {
                    grown[index(hash(keys[e]), len)].insert(0, e);
                }
            }
            buckets = grown;
        }
        let len = buckets.len();
        buckets[index(hash(key), len)].insert(0, i);
    }
    buckets.iter().rev().flatten().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_to_xml_layout() {
        let xml = store_to_xml(
            "file name mapping",
            &[("file_1", "a&b.pdf"), ("file_2", "<c>.pdf")],
            "\n",
        );
        let lines: Vec<&str> = xml.lines().collect();
        assert_eq!(
            lines[0],
            r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>"#
        );
        assert_eq!(
            lines[1],
            r#"<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">"#
        );
        assert_eq!(lines[2], "<properties>");
        assert_eq!(lines[3], "<comment>file name mapping</comment>");
        let mut entries = lines[4..6].to_vec();
        entries.sort();
        assert_eq!(
            entries,
            [
                r#"<entry key="file_1">a&amp;b.pdf</entry>"#,
                r#"<entry key="file_2">&lt;c&gt;.pdf</entry>"#
            ]
        );
        assert_eq!(lines[6], "</properties>");
        assert!(store_to_xml("", &[], "\r\n").ends_with("<properties>\r\n</properties>\r\n"));
    }

    #[test]
    fn hashtable_walks_buckets_from_the_last() {
        // "file_1".."file_3" hash to consecutive values: buckets 1, 2, 3 of 11 (computed with
        // Java's String.hashCode), walked from the last.
        let order = hashtable_order(&["file_1", "file_2", "file_3"]);
        let buckets: Vec<usize> = ["file_1", "file_2", "file_3"]
            .iter()
            .map(|k| ((oncl_pdk::javamap::string_hash(k) & 0x7fff_ffff) as usize) % 11)
            .collect();
        let mut expected = vec![0, 1, 2];
        expected.sort_by_key(|&i| std::cmp::Reverse(buckets[i]));
        assert_eq!(order, expected);
    }
}
