//! Meaningful XML for the proof: namespaced, `Id`-addressed records written in a
//! deliberately NON-canonical lexical form (single/double quotes, spaced `=`, character
//! references, CDATA, self-closing elements, unused namespace declarations, attributes out
//! of order) next to their exclusive-canonical form produced by a second code path from the
//! same logical values. The canonical digests of the `Id`-addressed elements and of the
//! whole document are accumulated while writing; nothing here calls a production parser.

use super::{CanonHash, FileDigests, HashingFile, Rng};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};

pub const NS_EX: &str = "urn:oncl:proof:archive";
pub const NS_REC: &str = "urn:oncl:proof:record";
pub const NS_LOC: &str = "urn:oncl:proof:loc";
pub const NS_UNUSED: &str = "urn:oncl:proof:unused";
pub const NS_SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const NS_WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XmlKind {
    /// `ex:archive` with header, three sections and a footer; `Id` attributes.
    Archive,
    /// SOAP 1.1 envelope: a large `soap:Header` ledger, then a `soap:Body` with `wsu:Id`.
    Soap,
}

/// A referenceable element: its raw byte extent and its standalone exclusive-canonical
/// (no comments) digest, which is the digest of an `#Id` reference to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElementFacts {
    pub id: String,
    pub start: u64,
    pub end: u64,
    pub canonical_sha256: String,
    pub canonical_len: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XmlFacts {
    pub kind: XmlKind,
    pub records: u64,
    pub elements: Vec<ElementFacts>,
    /// Exclusive canonical form of the document element without any signature.
    pub whole_canonical_sha256: String,
    pub whole_canonical_len: u64,
    /// Offset of the root end tag (where an enveloped signature is inserted as the last child).
    pub root_close_offset: u64,
    pub prefix_sha256_at_root_close: String,
    /// The exact raw bytes from the root end tag to the end of the file.
    pub suffix_after_root_close: String,
    /// Id of the element the far-reference cases sign.
    pub far_target: String,
    /// A byte inside `far_target` (an amount digit) and its original value.
    pub far_tamper_offset: u64,
    pub far_tamper_byte: u8,
    /// A byte of the document outside `far_target`, to show that an uncovered change stays valid.
    pub uncovered_tamper_offset: u64,
    pub uncovered_tamper_byte: u8,
}

const KK: &[&str] = &[
    "Құжат", "Жазба", "Төлем", "Шот-фактура", "Қазақстан", "Алматы", "Астана", "Қызмет",
    "Тапсырыс", "Келісімшарт", "Есеп", "Қолхат",
];
const RU: &[&str] = &["Договор", "Счёт", "Платёж", "Накладная", "Акт", "Приказ"];
const EN: &[&str] = &["Invoice", "Order", "Receipt", "Statement", "Ledger"];
const SPECIAL: &[&str] = &[
    "&", "<", ">", "\"", "'", "№", "€", "😀", "\t", "a&b<c>d", "\u{4B0}\u{4B1}", "]]", "]>",
];
const KINDS: &[&str] = &["invoice", "акт", "order", "шот", "note"];

/// Exclusive/inclusive canonical text escaping (Canonical XML 1.0 section 2.3).
pub fn escape_text(logical: &str, out: &mut Vec<u8>) {
    for c in logical.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
}

/// Canonical attribute escaping.
pub fn escape_attr(logical: &str, out: &mut Vec<u8>) {
    for c in logical.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
}

fn numeric_ref(c: char, out: &mut Vec<u8>) {
    use std::io::Write as _;
    let _ = write!(out, "&#{};", c as u32);
}

/// Raw (non-canonical) character data in one of three lexical styles.
fn raw_text(logical: &str, mode: u64, out: &mut Vec<u8>) {
    match mode % 3 {
        2 if !logical.contains("]]>") && !logical.contains('\r') => {
            out.extend_from_slice(b"<![CDATA[");
            out.extend_from_slice(logical.as_bytes());
            out.extend_from_slice(b"]]>");
        }
        1 => {
            for c in logical.chars() {
                match c {
                    '&' => out.extend_from_slice(b"&#x26;"),
                    '<' => out.extend_from_slice(b"&#x3C;"),
                    '>' => out.extend_from_slice(b"&gt;"),
                    '\r' => out.extend_from_slice(b"&#13;"),
                    '\'' => out.extend_from_slice(b"&apos;"),
                    '"' => out.extend_from_slice(b"&quot;"),
                    c if !c.is_ascii() => numeric_ref(c, out),
                    c => out.push(c as u8),
                }
            }
        }
        _ => {
            for c in logical.chars() {
                match c {
                    '&' => out.extend_from_slice(b"&amp;"),
                    '<' => out.extend_from_slice(b"&lt;"),
                    '>' => out.extend_from_slice(b"&gt;"),
                    '\r' => out.extend_from_slice(b"&#13;"),
                    _ => {
                        let mut b = [0u8; 4];
                        out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                    }
                }
            }
        }
    }
}

/// Raw attribute value, quoted with `quote` (`'` or `"`), whitespace controls as references.
fn raw_attr(logical: &str, quote: u8, mode: u64, out: &mut Vec<u8>) {
    out.push(quote);
    for c in logical.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '\'' if quote == b'\'' => out.extend_from_slice(b"&apos;"),
            '"' if quote == b'"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#9;"),
            '\n' => out.extend_from_slice(b"&#10;"),
            '\r' => out.extend_from_slice(b"&#13;"),
            c if !c.is_ascii() && mode % 2 == 1 => numeric_ref(c, out),
            _ => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    out.push(quote);
}

/// A phrase of `words` words (and occasionally a special token) from the vocabularies.
fn phrase(rng: &mut Rng, words: u64, specials: bool) -> String {
    let mut out = String::new();
    for w in 0..words {
        if w > 0 {
            out.push(' ');
        }
        let pick = rng.below(16);
        let word = match pick {
            0..=6 => KK[rng.below(KK.len() as u64) as usize],
            7..=10 => RU[rng.below(RU.len() as u64) as usize],
            11..=13 => EN[rng.below(EN.len() as u64) as usize],
            _ if specials => SPECIAL[rng.below(SPECIAL.len() as u64) as usize],
            _ => EN[rng.below(EN.len() as u64) as usize],
        };
        out.push_str(word);
    }
    out
}

/// One `rec:item` in both forms. `i` is the record number; a carriage return, tab and a
/// processing instruction appear at fixed rarities so the canonical rules for them are covered.
pub fn item(i: u64, rng: &mut Rng, raw: &mut Vec<u8>, canon: &mut Vec<u8>, pi: bool) {
    use std::io::Write as _;
    let mode = i;
    let kind = KINDS[(i % KINDS.len() as u64) as usize];
    let title = phrase(rng, 3 + i % 4, true);
    let mut note = phrase(rng, 6 + i % 9, true);
    if i % 97 == 0 {
        note.push_str("\r\n line two\ttabbed");
    }
    let target = format!("T{}-{}", i % 10007, rng.below(1_000_000));
    let amount = format!("{}.{:02}", rng.below(10_000_000), rng.below(100));
    let mut blob_bytes = [0u8; 48];
    rng.fill(&mut blob_bytes);
    let blob = base64::engine::general_purpose::STANDARD.encode(blob_bytes);
    let (q1, q2) = if i % 2 == 0 { (b'\'', b'"') } else { (b'"', b'\'') };

    // --- raw ---
    raw.extend_from_slice(b"\n    <rec:item  seq = ");
    raw_attr(&i.to_string(), q1, mode, raw);
    raw.extend_from_slice(b"  kind=");
    raw_attr(kind, q2, mode, raw);
    raw.extend_from_slice(b" xmlns:loc=");
    raw_attr(NS_LOC, q1, 0, raw);
    raw.extend_from_slice(b" xmlns:unused=");
    raw_attr(NS_UNUSED, q2, 0, raw);
    raw.extend_from_slice(b" title=");
    raw_attr(&title, q1, mode, raw);
    raw.extend_from_slice(b" >\n      <rec:title xml:lang=");
    raw_attr("kk", q2, 0, raw);
    raw.push(b'>');
    raw_text(&title, mode, raw);
    raw.extend_from_slice(b"</rec:title>\n      <loc:ref loc:target=");
    raw_attr(&target, q2, 0, raw);
    raw.extend_from_slice(b"  xml:lang=");
    raw_attr("ru", q1, 0, raw);
    raw.extend_from_slice(b" />\n      <rec:note>");
    raw_text(&note, mode + 1, raw);
    raw.extend_from_slice(b"</rec:note>\n      <rec:amount cur=");
    raw_attr("KZT", q1, 0, raw);
    let _ = write!(raw, ">{amount}</rec:amount>\n      <rec:blob>{blob}</rec:blob>");
    raw.extend_from_slice(b"\n      <rec:lines>");
    let line_count = 1 + i % 4;
    // --- canonical ---
    canon.extend_from_slice(b"\n    <rec:item xmlns:rec=\"");
    canon.extend_from_slice(NS_REC.as_bytes());
    canon.extend_from_slice(b"\" kind=\"");
    escape_attr(kind, canon);
    let _ = write!(canon, "\" seq=\"{i}\" title=\"");
    escape_attr(&title, canon);
    canon.extend_from_slice(b"\">\n      <rec:title xml:lang=\"kk\">");
    escape_text(&title, canon);
    canon.extend_from_slice(b"</rec:title>\n      <loc:ref xmlns:loc=\"");
    canon.extend_from_slice(NS_LOC.as_bytes());
    canon.extend_from_slice(b"\" xml:lang=\"ru\" loc:target=\"");
    escape_attr(&target, canon);
    canon.extend_from_slice(b"\"></loc:ref>\n      <rec:note>");
    escape_text(&note, canon);
    let _ = write!(
        canon,
        "</rec:note>\n      <rec:amount cur=\"KZT\">{amount}</rec:amount>\n      <rec:blob>{blob}</rec:blob>\n      <rec:lines>"
    );
    for n in 0..line_count {
        let sku = format!("SKU-{:05}", rng.below(100_000));
        let qty = rng.below(1000);
        if n == line_count - 1 && i % 3 == 0 {
            // self-closing in raw, start/end pair in canonical
            let _ = write!(raw, "<rec:line n='{n}' sku=\"{sku}\"/>");
            let _ = write!(canon, "<rec:line n=\"{n}\" sku=\"{sku}\"></rec:line>");
        } else {
            let _ = write!(raw, "<rec:line n=\"{n}\" sku='{sku}'>{qty}</rec:line>");
            let _ = write!(canon, "<rec:line n=\"{n}\" sku=\"{sku}\">{qty}</rec:line>");
        }
    }
    raw.extend_from_slice(b"</rec:lines>\n    </rec:item>");
    canon.extend_from_slice(b"</rec:lines>\n    </rec:item>");
    if i % 50 == 7 {
        // a comment between records: dropped by canonicalization without comments
        let _ = write!(raw, "<!-- record {i} -->");
    }
    if pi && i % 4096 == 11 {
        // a processing instruction (never in SOAP: SOAP 1.1 forbids them): kept by canonicalization
        let _ = write!(raw, "<?audit seq={i}?>");
        let _ = write!(canon, "<?audit seq={i}?>");
    }
}

struct Emitter<'f> {
    file: &'f mut HashingFile,
    /// Processing instructions inside records (not allowed in a SOAP message).
    pi: bool,
    whole: CanonHash,
    active: Option<(String, u64, CanonHash)>,
    elements: Vec<ElementFacts>,
}

impl Emitter<'_> {
    /// Raw bytes with identical canonical bytes (text nodes, tags without namespaces).
    fn same(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.put(bytes, bytes)
    }

    fn put(&mut self, raw: &[u8], canon: &[u8]) -> std::io::Result<()> {
        self.file.write_all(raw)?;
        self.whole.update(canon);
        if let Some((_, _, h)) = &mut self.active {
            h.update(canon);
        }
        Ok(())
    }

    /// Opens an element that later records belong to: `canon_in_doc` is its canonical open
    /// tag inside the document, `canon_standalone` the one a `#Id` reference canonicalizes.
    fn open(
        &mut self,
        id: &str,
        raw: &[u8],
        canon_in_doc: &[u8],
        canon_standalone: &[u8],
    ) -> std::io::Result<()> {
        let start = self.file.position();
        let mut h = CanonHash::default();
        h.update(canon_standalone);
        self.file.write_all(raw)?;
        self.whole.update(canon_in_doc);
        self.active = Some((id.to_owned(), start, h));
        Ok(())
    }

    fn close(&mut self, raw: &[u8]) -> std::io::Result<()> {
        self.put(raw, raw)?;
        let (id, start, h) = self.active.take().expect("an open element");
        let (digest, len) = h.finish();
        self.elements.push(ElementFacts {
            id,
            start,
            end: self.file.position(),
            canonical_sha256: digest,
            canonical_len: len,
        });
        Ok(())
    }
}

/// Largest record plus slack; the tail reserve of the exact-size pad.
const RECORD_BYTES_MAX: u64 = 4096;

/// The first digit of the amount of the first record that starts at or after `watch`.
type Tamper = Option<(u64, u8)>;

/// Emits records into the active element until the file position reaches `until`; remembers
/// the first amount digit at or after `watch` in `found`.
fn records(
    em: &mut Emitter<'_>,
    rng: &mut Rng,
    next: &mut u64,
    until: u64,
    watch: Option<u64>,
    found: &mut Tamper,
) -> std::io::Result<()> {
    let mut raw = Vec::with_capacity(2048);
    let mut canon = Vec::with_capacity(2048);
    while em.file.position() < until {
        raw.clear();
        canon.clear();
        item(*next, rng, &mut raw, &mut canon, em.pi);
        if let Some(watch) = watch
            && found.is_none()
            && em.file.position() >= watch
        {
            let marker = b"<rec:amount cur=";
            if let Some(at) = raw.windows(marker.len()).position(|w| w == marker) {
                let gt = at + raw[at..].iter().position(|b| *b == b'>').unwrap_or(0) + 1;
                *found = Some((em.file.position() + gt as u64, raw[gt]));
            }
        }
        em.put(&raw, &canon)?;
        *next += 1;
    }
    Ok(())
}

/// Writes one proof XML of exactly `total` bytes.
pub fn generate(
    path: &Path,
    total: u64,
    seed: u64,
    kind: XmlKind,
) -> std::io::Result<(XmlFacts, FileDigests)> {
    assert!(total >= 64 * 1024, "a proof XML needs at least 64 KiB");
    let mut file = HashingFile::create(path, false)?;
    let mut rng = Rng::new(seed);
    let mut em = Emitter {
        file: &mut file,
        pi: kind == XmlKind::Archive,
        whole: CanonHash::default(),
        active: None,
        elements: Vec::new(),
    };
    let mut next = 0u64;
    let mut far_tamper: Tamper = None;
    let mut uncovered_tamper: Tamper = None;
    let far_target;
    let root_close;
    let prefix_at_close;
    let suffix;
    let tail_reserve = 2048 + RECORD_BYTES_MAX;
    em.file
        .write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    match kind {
        XmlKind::Archive => {
            far_target = "section-2".to_owned();
            let root_raw = format!(
                "<ex:archive xmlns:ex='{NS_EX}' xmlns:rec=\"{NS_REC}\" xmlns:unused='{NS_UNUSED}' Id=\"archive\" generated='2026-11-04' >"
            );
            let root_canon =
                format!("<ex:archive xmlns:ex=\"{NS_EX}\" Id=\"archive\" generated=\"2026-11-04\">");
            em.put(root_raw.as_bytes(), root_canon.as_bytes())?;
            em.put(b"\n  ", b"\n  ")?;
            let header_alone = format!("<ex:header xmlns:ex=\"{NS_EX}\" Id=\"header\">");
            em.open(
                "header",
                b"<ex:header Id='header'><!-- fixed header -->",
                b"<ex:header Id=\"header\">",
                header_alone.as_bytes(),
            )?;
            em.same(b"<ex:created>2026-11-04T00:00:00Z</ex:created>")?;
            em.close(b"</ex:header>")?;
            let sections = [
                ("section-0", (total as f64 * 0.22) as u64),
                ("section-1", (total as f64 * 0.52) as u64),
                ("section-2", total - tail_reserve),
            ];
            for (index, (id, until)) in sections.iter().enumerate() {
                em.put(b"\n  ", b"\n  ")?;
                let raw = format!("<ex:section  Id = '{id}'  index=\"{index}\">");
                let in_doc = format!("<ex:section Id=\"{id}\" index=\"{index}\">");
                let alone =
                    format!("<ex:section xmlns:ex=\"{NS_EX}\" Id=\"{id}\" index=\"{index}\">");
                em.open(id, raw.as_bytes(), in_doc.as_bytes(), alone.as_bytes())?;
                let watch = Some(em.file.position() + 1024);
                match index {
                    0 => records(&mut em, &mut rng, &mut next, *until, watch, &mut uncovered_tamper)?,
                    2 => records(&mut em, &mut rng, &mut next, *until, watch, &mut far_tamper)?,
                    _ => records(&mut em, &mut rng, &mut next, *until, None, &mut None)?,
                }
                em.close(b"\n  </ex:section>")?;
            }
            em.put(b"\n  ", b"\n  ")?;
            let footer_head = "<ex:footer Id=\"footer\"><ex:pad>";
            let footer_tail = "</ex:pad></ex:footer>";
            let root_tail = "</ex:archive>\n";
            let fixed = footer_head.len() + footer_tail.len() + 1 + root_tail.len();
            let pad_len = total
                .checked_sub(em.file.position() + fixed as u64)
                .expect("the tail reserve covers the footer");
            let footer_alone = format!("<ex:footer xmlns:ex=\"{NS_EX}\" Id=\"footer\"><ex:pad>");
            em.open(
                "footer",
                footer_head.as_bytes(),
                footer_head.as_bytes(),
                footer_alone.as_bytes(),
            )?;
            em.same("x".repeat(pad_len as usize).as_bytes())?;
            em.close(footer_tail.as_bytes())?;
            em.put(b"\n", b"\n")?;
            root_close = em.file.position();
            prefix_at_close = em.file.prefix_sha256();
            em.file.write_all(root_tail.as_bytes())?;
            em.whole.update(b"</ex:archive>");
            suffix = root_tail.to_owned();
        }
        XmlKind::Soap => {
            far_target = "body-1".to_owned();
            let root_raw = format!(
                "<soap:Envelope xmlns:soap='{NS_SOAP}' xmlns:wsu=\"{NS_WSU}\" xmlns:rec='{NS_REC}' xmlns:unused=\"{NS_UNUSED}\">"
            );
            let root_canon = format!("<soap:Envelope xmlns:soap=\"{NS_SOAP}\">");
            em.put(root_raw.as_bytes(), root_canon.as_bytes())?;
            em.put(b"\n  <soap:Header>\n    ", b"\n  <soap:Header>\n    ")?;
            // `ex` and `wsu` are first utilized by the ledger, in the document and alone.
            let ledger_raw = format!("<ex:ledger xmlns:ex='{NS_EX}' wsu:Id=\"ledger-1\">");
            let ledger_canon = format!(
                "<ex:ledger xmlns:ex=\"{NS_EX}\" xmlns:wsu=\"{NS_WSU}\" wsu:Id=\"ledger-1\">"
            );
            em.open(
                "ledger-1",
                ledger_raw.as_bytes(),
                ledger_canon.as_bytes(),
                ledger_canon.as_bytes(),
            )?;
            let ledger_until = (total as f64 * 0.45) as u64;
            let watch = Some(em.file.position() + 1024);
            records(&mut em, &mut rng, &mut next, ledger_until, watch, &mut uncovered_tamper)?;
            em.close(b"\n    </ex:ledger>")?;
            em.put(b"\n  </soap:Header>\n  ", b"\n  </soap:Header>\n  ")?;
            let body_in_doc = format!("<soap:Body xmlns:wsu=\"{NS_WSU}\" wsu:Id=\"body-1\">");
            let body_alone = format!(
                "<soap:Body xmlns:soap=\"{NS_SOAP}\" xmlns:wsu=\"{NS_WSU}\" wsu:Id=\"body-1\">"
            );
            em.open(
                "body-1",
                b"<soap:Body wsu:Id='body-1'>",
                body_in_doc.as_bytes(),
                body_alone.as_bytes(),
            )?;
            let watch = Some(em.file.position() + 1024);
            records(
                &mut em,
                &mut rng,
                &mut next,
                total - tail_reserve,
                watch,
                &mut far_tamper,
            )?;
            let pad_head = "\n    <rec:pad>";
            let pad_tail = "</rec:pad>";
            let body_tail = "\n  </soap:Body>";
            let root_tail = "</soap:Envelope>\n";
            let fixed = pad_head.len() + pad_tail.len() + body_tail.len() + 1 + root_tail.len();
            let pad_len = total
                .checked_sub(em.file.position() + fixed as u64)
                .expect("the tail reserve covers the pad");
            em.put(
                pad_head.as_bytes(),
                format!("\n    <rec:pad xmlns:rec=\"{NS_REC}\">").as_bytes(),
            )?;
            em.same("y".repeat(pad_len as usize).as_bytes())?;
            em.same(pad_tail.as_bytes())?;
            em.close(body_tail.as_bytes())?;
            em.put(b"\n", b"\n")?;
            root_close = em.file.position();
            prefix_at_close = em.file.prefix_sha256();
            em.file.write_all(root_tail.as_bytes())?;
            em.whole.update(b"</soap:Envelope>");
            suffix = root_tail.to_owned();
        }
    }
    let (whole_sha, whole_len) = std::mem::take(&mut em.whole).finish();
    let elements = std::mem::take(&mut em.elements);
    drop(em);
    let digests = file.finish()?;
    assert_eq!(digests.len, total, "the proof XML must have the exact size");
    let (far_offset, far_byte) = far_tamper.expect("a far tamper position exists");
    let (uncovered_offset, uncovered_byte) =
        uncovered_tamper.expect("an uncovered tamper position exists");
    let facts = XmlFacts {
        kind,
        records: next,
        elements,
        whole_canonical_sha256: whole_sha,
        whole_canonical_len: whole_len,
        root_close_offset: root_close,
        prefix_sha256_at_root_close: prefix_at_close,
        suffix_after_root_close: suffix,
        far_target,
        far_tamper_offset: far_offset,
        far_tamper_byte: far_byte,
        uncovered_tamper_offset: uncovered_offset,
        uncovered_tamper_byte: uncovered_byte,
    };
    Ok((facts, digests))
}
