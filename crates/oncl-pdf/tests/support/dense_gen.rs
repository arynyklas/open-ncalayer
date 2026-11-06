//! An independent writer of dense PDFs (no PDF library, no oncl code): a two-level page
//! tree whose pages each own a small content stream, in classic-xref or
//! object-stream + cross-reference-stream form, with incremental updates.
#![allow(dead_code)]
use std::io::Write;

const PER_NODE: usize = 200;
const PER_OBJSTM: usize = 100;
const ID: &str = "/ID [<11111111111111111111111111111111> <11111111111111111111111111111111>]";

pub struct Dense {
    pub bytes: Vec<u8>,
    /// `/Size` of the last cross-reference section.
    pub size: u32,
    /// Cross-reference entries over all revisions, as a reader must count them.
    pub entries: u64,
    pub pages: usize,
}

fn layout(objects: usize) -> (usize, usize, u32, u32) {
    let mut pages = ((objects - 2) / 2).max(1);
    let mut nodes = pages.div_ceil(PER_NODE);
    pages = ((objects - 2 - nodes) / 2).max(1);
    nodes = pages.div_ceil(PER_NODE);
    let first_node = 3;
    (pages, nodes, first_node, first_node + nodes as u32)
}

/// `(number, is_stream, body)` of every base object, ascending.
type Objects = Vec<(u32, bool, Vec<u8>)>;
fn base_objects(objects: usize) -> (Objects, usize, u32, u32) {
    let (pages, nodes, first_node, first_page) = layout(objects);
    let mut out = vec![(1, false, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec())];
    let kids: Vec<String> = (0..nodes)
        .map(|n| format!("{} 0 R", first_node + n as u32))
        .collect();
    out.push((
        2,
        false,
        format!(
            "<< /Type /Pages /Count {pages} /Kids [{}] >>",
            kids.join(" ")
        )
        .into_bytes(),
    ));
    for n in 0..nodes {
        let (lo, hi) = (n * PER_NODE, pages.min((n + 1) * PER_NODE));
        let kids: Vec<String> = (lo..hi)
            .map(|p| format!("{} 0 R", first_page + 2 * p as u32))
            .collect();
        out.push((
            first_node + n as u32,
            false,
            format!(
                "<< /Type /Pages /Parent 2 0 R /Count {} /Kids [{}] >>",
                hi - lo,
                kids.join(" ")
            )
            .into_bytes(),
        ));
    }
    for p in 0..pages {
        let id = first_page + 2 * p as u32;
        let node = first_node + (p / PER_NODE) as u32;
        out.push((
            id,
            false,
            format!(
                "<< /Type /Page /Parent {node} 0 R /MediaBox [0 0 612 792] /Contents {} 0 R >>",
                id + 1
            )
            .into_bytes(),
        ));
        out.push((
            id + 1,
            true,
            format!("BT /F1 12 Tf 72 720 Td (page {p}) Tj ET").into_bytes(),
        ));
    }
    (out, pages, first_node, first_page)
}

fn object(number: u32, is_stream: bool, body: &[u8]) -> Vec<u8> {
    if is_stream {
        let mut out =
            format!("{number} 0 obj\n<< /Length {} >>\nstream\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        out
    } else {
        let mut out = format!("{number} 0 obj\n").into_bytes();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
        out
    }
}

fn rewritten_page(first_page: u32, revision: usize) -> (u32, Vec<u8>) {
    let id = first_page + 2 * (revision as u32 - 1);
    let node = 3 + (revision as u32 - 1) / PER_NODE as u32;
    (
        id,
        format!(
            "<< /Type /Page /Parent {node} 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Rotate 0 >>",
            id + 1
        )
        .into_bytes(),
    )
}

fn header() -> Vec<u8> {
    b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec()
}

/// A classic-xref document of about `objects` objects and `revisions` revisions (each
/// later one re-writes one page and lists only it).
pub fn classic(objects: usize, revisions: usize) -> Dense {
    let (base, pages, _, first_page) = base_objects(objects);
    let mut out = header();
    let mut offsets = Vec::new();
    for (number, is_stream, body) in &base {
        offsets.push((*number, out.len()));
        out.extend(object(*number, *is_stream, body));
    }
    let size = base.last().map_or(1, |o| o.0 + 1);
    let mut startxref = out.len();
    let mut table = format!("xref\n0 1\n0000000000 65535 f \n1 {}\n", offsets.len());
    for (_, offset) in &offsets {
        table.push_str(&format!("{offset:010} 00000 n \n"));
    }
    out.extend(table.into_bytes());
    out.extend(
        format!("trailer\n<< /Size {size} /Root 1 0 R {ID} >>\nstartxref\n{startxref}\n%%EOF\n")
            .into_bytes(),
    );
    let mut entries = 1 + offsets.len() as u64;
    for revision in 1..revisions {
        let (number, body) = rewritten_page(first_page, revision);
        let at = out.len();
        out.extend(object(number, false, &body));
        let previous = startxref;
        startxref = out.len();
        out.extend(format!("xref\n{number} 1\n{at:010} 00000 n \ntrailer\n<< /Size {size} /Root 1 0 R /Prev {previous} {ID} >>\nstartxref\n{startxref}\n%%EOF\n").into_bytes());
        entries += 1;
    }
    Dense {
        bytes: out,
        size,
        entries,
        pages,
    }
}

pub fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// PNG "up" predictor rows of `width` bytes.
pub fn png_up(raw: &[u8], width: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / width + 1);
    let mut previous = vec![0u8; width];
    for row in raw.chunks(width) {
        out.push(2);
        out.extend(row.iter().zip(&previous).map(|(a, b)| a.wrapping_sub(*b)));
        previous = row.to_vec();
    }
    out
}

fn row(kind: u8, second: u32, third: u16) -> [u8; 7] {
    let mut out = [0u8; 7];
    out[0] = kind;
    out[1..5].copy_from_slice(&second.to_be_bytes());
    out[5..7].copy_from_slice(&third.to_be_bytes());
    out
}

/// Pages and the page tree in object streams, content streams direct, a Flate
/// cross-reference stream (`W [1 4 2]`, PNG-up predictor when `predictor`).
pub fn streamed(objects: usize, revisions: usize, predictor: bool) -> Dense {
    let (base, pages, _, first_page) = base_objects(objects);
    let mut out = header();
    let mut rows: std::collections::BTreeMap<u32, [u8; 7]> = Default::default();
    let size0 = base.last().map_or(1, |o| o.0 + 1);
    let mut next = size0;
    for (number, is_stream, body) in base.iter().filter(|o| o.1) {
        rows.insert(*number, row(1, out.len() as u32, 0));
        out.extend(object(*number, *is_stream, body));
    }
    let packed: Vec<_> = base.iter().filter(|o| !o.1).collect();
    for chunk in packed.chunks(PER_OBJSTM) {
        let (mut head, mut data) = (String::new(), Vec::new());
        for (index, (number, _, body)) in chunk.iter().enumerate() {
            head.push_str(&format!("{number} {} ", data.len()));
            data.extend_from_slice(body);
            data.push(b'\n');
            rows.insert(*number, row(2, next, index as u16));
        }
        let mut payload = head.clone().into_bytes();
        payload.extend(data);
        let payload = zlib(&payload);
        rows.insert(next, row(1, out.len() as u32, 0));
        out.extend(format!("{next} 0 obj\n<< /Type /ObjStm /N {} /First {} /Filter /FlateDecode /Length {} >>\nstream\n", chunk.len(), head.len(), payload.len()).into_bytes());
        out.extend(payload);
        out.extend(b"\nendstream\nendobj\n");
        next += 1;
    }
    let xref_number = next;
    let size = xref_number + 1;
    let mut startxref = out.len();
    rows.insert(xref_number, row(1, startxref as u32, 0));
    rows.insert(0, row(0, 0, 65535));
    let raw: Vec<u8> = (0..size).flat_map(|n| rows[&n]).collect();
    let encoded = if predictor {
        zlib(&png_up(&raw, 7))
    } else {
        zlib(&raw)
    };
    let parms = if predictor {
        " /DecodeParms << /Predictor 12 /Columns 7 >>"
    } else {
        ""
    };
    out.extend(format!("{xref_number} 0 obj\n<< /Type /XRef /Size {size} /W [1 4 2] /Root 1 0 R {ID} /Filter /FlateDecode{parms} /Length {} >>\nstream\n", encoded.len()).into_bytes());
    out.extend(encoded);
    out.extend(format!("\nendstream\nendobj\nstartxref\n{startxref}\n%%EOF\n").into_bytes());
    let mut entries = u64::from(size);
    let mut size = size;
    for revision in 1..revisions {
        let (number, body) = rewritten_page(first_page, revision);
        let at = out.len();
        out.extend(object(number, false, &body));
        let previous = startxref;
        let xref_number = size;
        size += 1;
        startxref = out.len();
        let mut raw = row(1, at as u32, 0).to_vec();
        raw.extend(row(1, startxref as u32, 0));
        let encoded = if predictor {
            zlib(&png_up(&raw, 7))
        } else {
            zlib(&raw)
        };
        out.extend(format!("{xref_number} 0 obj\n<< /Type /XRef /Size {size} /W [1 4 2] /Index [{number} 1 {xref_number} 1] /Root 1 0 R /Prev {previous} {ID} /Filter /FlateDecode{parms} /Length {} >>\nstream\n", encoded.len()).into_bytes());
        out.extend(encoded);
        out.extend(format!("\nendstream\nendobj\nstartxref\n{startxref}\n%%EOF\n").into_bytes());
        entries += 2;
    }
    Dense {
        bytes: out,
        size,
        entries,
        pages,
    }
}

/// A one-revision classic document whose xref table is exactly `table` (the text between
/// `xref\n` and `trailer`), for hostile tables.
pub fn classic_with_table(table: &str) -> Vec<u8> {
    classic_with_table_size(table, 3)
}
pub fn classic_with_table_size(table: &str, size: u32) -> Vec<u8> {
    let mut out = header();
    out.extend(object(1, false, b"<< /Type /Catalog /Pages 2 0 R >>"));
    let startxref = out.len();
    out.extend(
        format!(
            "xref\n{table}trailer\n<< /Size {size} /Root 1 0 R {ID} >>\nstartxref\n{startxref}\n%%EOF\n"
        )
        .into_bytes(),
    );
    out
}

/// A one-revision document whose cross-reference stream carries `dictionary_tail`
/// (extra entries of its dictionary: `/Index`, `/W`, `/Size`...) and the exact `payload`.
pub fn xref_stream_with(dictionary: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = header();
    out.extend(object(1, false, b"<< /Type /Catalog /Pages 2 0 R >>"));
    let startxref = out.len();
    out.extend(
        format!(
            "2 0 obj\n<< /Type /XRef /Root 1 0 R {ID} {dictionary} /Length {} >>\nstream\n",
            payload.len()
        )
        .into_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend(format!("\nendstream\nendobj\nstartxref\n{startxref}\n%%EOF\n").into_bytes());
    out
}
