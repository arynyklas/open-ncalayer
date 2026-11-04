//! Meaningful PDF for the proof: a page tree three levels deep, per-page content streams
//! with unique text and per-page raw RGB image streams of pseudo-random pixels, a classic
//! cross-reference table for the first revision, and two incremental revisions that use
//! cross-reference streams (64-bit offset fields), object streams (zlib "stored" blocks, at
//! most 100 objects each) and replaced objects (the page-tree root, then the catalog); the
//! last revision carries one large embedded file that sizes the document to the byte.
//!
//! Nothing here reads a PDF: every number written (offsets, counts, lengths) comes from the
//! generator's own bookkeeping, and `platform-proof` checks small instances with pyHanko.

use super::{FileDigests, HashingFile, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfProfile {
    /// Tens of thousands of small objects (about 200 KiB of image per page): the shape of a
    /// scanned archive.
    Dense,
    /// A few hundred large pages (about 10 MiB of image each), within the default
    /// `PdfLimits::max_objects`.
    Compact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevisionFacts {
    pub kind: String,
    pub start: u64,
    pub end: u64,
    pub startxref: u64,
    pub objects_after: u64,
    pub object_streams: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PdfFacts {
    pub profile: PdfProfile,
    pub pages: u64,
    pub revisions: Vec<RevisionFacts>,
    pub embedded_offset: u64,
    pub embedded_len: u64,
    pub embedded_sha256: String,
    /// `(page index, text drawn on it)` for a first, middle and last page.
    pub samples: Vec<(u64, String)>,
    pub final_startxref: u64,
}

const GROUP: u64 = 64;
const OBJSTM_MAX: usize = 100;

fn ceil_div(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

/// zlib stream made only of stored (uncompressed) deflate blocks.
pub fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 16);
    out.extend_from_slice(&[0x78, 0x01]);
    let mut chunks = data.chunks(65535).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

struct Plan {
    image_w: u64,
    image_h: u64,
    p1: u64,
    p2: u64,
}

impl Plan {
    fn new(total: u64, profile: PdfProfile) -> Self {
        let image_bytes: u64 = match profile {
            PdfProfile::Dense => 256 * 256 * 3,
            PdfProfile::Compact => (total / 1100).clamp(64 * 1024, 10 * 1024 * 1024),
        };
        // width x height x 3 close to the target, width 4 aligned
        let side = ((image_bytes / 3) as f64).sqrt() as u64;
        let (image_w, image_h) = (side.max(8), (image_bytes / 3 / side.max(8)).max(8));
        let per_page = image_w * image_h * 3 + 900;
        let p1 = ((total as f64 * 0.45) as u64 / per_page).max(4);
        let p2 = ((total as f64 * 0.35) as u64 / per_page).max(4);
        Self {
            image_w,
            image_h,
            p1,
            p2,
        }
    }
}

fn hex_id(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64())
}

#[derive(Clone, Copy)]
enum Entry {
    Plain(u64),
    Packed { stream: u64, index: u16 },
}

struct Writer<'f> {
    file: &'f mut HashingFile,
}

impl Writer<'_> {
    fn begin_obj(&mut self, num: u64) -> std::io::Result<u64> {
        let at = self.file.position();
        write!(self.file, "{num} 0 obj\n")?;
        Ok(at)
    }

    fn object(&mut self, num: u64, body: &str) -> std::io::Result<u64> {
        let at = self.begin_obj(num)?;
        write!(self.file, "{body}\nendobj\n")?;
        Ok(at)
    }

    fn stream(&mut self, num: u64, dict: &str, data: &[u8]) -> std::io::Result<u64> {
        let at = self.begin_obj(num)?;
        write!(
            self.file,
            "<< {dict} /Length {} >>\nstream\n",
            data.len()
        )?;
        self.file.write_all(data)?;
        self.file.write_all(b"\nendstream\nendobj\n")?;
        Ok(at)
    }
}

fn page_dict(parent: u64, content: u64, image: u64) -> String {
    format!(
        "<< /Type /Page /Parent {parent} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> /XObject << /Im0 {image} 0 R >> >> /Contents {content} 0 R >>"
    )
}

fn page_text(index: u64, total: u64, rng: &mut Rng) -> String {
    format!(
        "ONCL proof page {} of {total}; ledger KZ-{:08} amount {}.{:02} status reviewed",
        index + 1,
        rng.below(100_000_000),
        rng.below(1_000_000),
        rng.below(100)
    )
}

fn content_stream(text: &str, line2: &str, w: u64, h: u64) -> Vec<u8> {
    let _ = (w, h);
    format!(
        "BT /F1 14 Tf 56 780 Td ({text}) Tj ET\nBT /F1 10 Tf 56 760 Td ({line2}) Tj ET\nq 400 0 0 400 56 300 cm /Im0 Do Q\n"
    )
    .into_bytes()
}

fn pages_node(parent: u64, kids: &[u64], count: u64) -> String {
    let mut s = format!("<< /Type /Pages /Parent {parent} 0 R /Kids [");
    for (i, k) in kids.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{k} 0 R"));
    }
    s.push_str(&format!("] /Count {count} >>"));
    s
}

fn xref_stream_data(entries: &[(u64, Entry)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 11);
    for (_, e) in entries {
        match *e {
            Entry::Plain(offset) => {
                out.push(1);
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            Entry::Packed { stream, index } => {
                out.push(2);
                out.extend_from_slice(&stream.to_be_bytes());
                out.extend_from_slice(&index.to_be_bytes());
            }
        }
    }
    out
}

/// `/Index` subsections of ascending, deduplicated object numbers.
fn index_array(entries: &[(u64, Entry)]) -> String {
    let mut out = String::from("[");
    let mut i = 0;
    while i < entries.len() {
        let first = entries[i].0;
        let mut n = 1;
        while i + n < entries.len() && entries[i + n].0 == first + n as u64 {
            n += 1;
        }
        out.push_str(&format!("{first} {n} "));
        i += n;
    }
    out.pop();
    out.push(']');
    out
}

/// One object stream (`/Type /ObjStm`) of `(object number, serialized object)` pairs.
fn object_stream(objects: &[(u64, String)]) -> (Vec<u8>, usize) {
    let mut header = String::new();
    let mut body = String::new();
    for (num, text) in objects {
        header.push_str(&format!("{num} {} ", body.len()));
        body.push_str(text);
        body.push('\n');
    }
    let first = header.len();
    let mut data = header.into_bytes();
    data.extend_from_slice(body.as_bytes());
    (zlib_stored(&data), first)
}

/// Writes a proof PDF of exactly `total` bytes.
pub fn generate(
    path: &Path,
    total: u64,
    seed: u64,
    profile: PdfProfile,
) -> std::io::Result<(PdfFacts, FileDigests)> {
    assert!(total >= 2 * 1024 * 1024, "a proof PDF needs at least 2 MiB");
    let plan = Plan::new(total, profile);
    let mut file = HashingFile::create(path, false)?;
    let mut rng = Rng::new(seed);
    let id = hex_id(seed);
    let all_pages = plan.p1 + plan.p2;
    let image_len = (plan.image_w * plan.image_h * 3) as usize;
    let mut image = vec![0u8; image_len];
    let mut w = Writer { file: &mut file };
    let mut samples = Vec::new();
    let mut revisions = Vec::new();

    // ---------------------------------------------------------------- revision 1
    w.file.write_all(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")?;
    let g1 = ceil_div(plan.p1, GROUP);
    let a1 = ceil_div(g1, GROUP);
    let l1_base = 5;
    let l2_base = l1_base + a1;
    let page_base = l2_base + g1;
    let n1 = page_base + 3 * plan.p1;
    let mut r1: Vec<u64> = vec![0; n1 as usize];
    r1[1] = w.object(
        1,
        "<< /Type /Catalog /Pages 2 0 R /Lang (kk-KZ) /ViewerPreferences << /DisplayDocTitle true >> >>",
    )?;
    let l1_kids: Vec<u64> = (0..a1).map(|i| l1_base + i).collect();
    r1[2] = w.object(2, &pages_node_root(&l1_kids, plan.p1))?;
    r1[3] = w.object(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")?;
    r1[4] = w.object(
        4,
        "<< /Title (ONCL platform proof document) /Producer (xtask reference generator) /CreationDate (D:20261104000000Z) >>",
    )?;
    for a in 0..a1 {
        let first = a * GROUP;
        let last = ((a + 1) * GROUP).min(g1);
        let kids: Vec<u64> = (first..last).map(|g| l2_base + g).collect();
        let count = (first * GROUP..(last * GROUP).min(plan.p1)).count() as u64;
        r1[(l1_base + a) as usize] = w.object(l1_base + a, &pages_node(2, &kids, count))?;
    }
    for g in 0..g1 {
        let first = g * GROUP;
        let last = ((g + 1) * GROUP).min(plan.p1);
        let kids: Vec<u64> = (first..last).map(|k| page_base + 3 * k).collect();
        let parent = l1_base + g / GROUP;
        r1[(l2_base + g) as usize] = w.object(l2_base + g, &pages_node(parent, &kids, last - first))?;
    }
    for k in 0..plan.p1 {
        let num = page_base + 3 * k;
        let text = page_text(k, all_pages, &mut rng);
        let line2 = format!("revision 1 object {num}");
        rng.fill(&mut image);
        let parent = l2_base + k / GROUP;
        r1[num as usize] = w.object(num, &page_dict(parent, num + 1, num + 2))?;
        r1[num as usize + 1] = w.stream(num + 1, "", &content_stream(&text, &line2, plan.image_w, plan.image_h))?;
        r1[num as usize + 2] = w.stream(
            num + 2,
            &format!(
                "/Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB /BitsPerComponent 8",
                plan.image_w, plan.image_h
            ),
            &image,
        )?;
        if k == 0 || k == plan.p1 / 2 || k == plan.p1 - 1 {
            samples.push((k, text));
        }
    }
    let xref1 = w.file.position();
    w.file.write_all(format!("xref\n0 {n1}\n0000000000 65535 f \n").as_bytes())?;
    for offset in &r1[1..] {
        w.file.write_all(format!("{offset:010} 00000 n \n").as_bytes())?;
    }
    w.file.write_all(
        format!(
            "trailer\n<< /Size {n1} /Root 1 0 R /Info 4 0 R /ID [<{id}> <{id}>] >>\nstartxref\n{xref1}\n%%EOF\n"
        )
        .as_bytes(),
    )?;
    revisions.push(RevisionFacts {
        kind: "xref-table".into(),
        start: 0,
        end: w.file.position(),
        startxref: xref1,
        objects_after: n1,
        object_streams: 0,
    });

    // ---------------------------------------------------------------- revision 2
    let r2_start = w.file.position();
    let g2 = ceil_div(plan.p2, GROUP);
    let a2 = ceil_div(g2, GROUP);
    let l1_base2 = n1;
    let l2_base2 = l1_base2 + a2;
    let page_base2 = l2_base2 + g2;
    let packed_count = 1 + a2 + g2 + plan.p2;
    let containers2 = ceil_div(packed_count, OBJSTM_MAX as u64);
    let stm_base2 = page_base2 + 3 * plan.p2;
    let xref_obj2 = stm_base2 + containers2;
    let n2 = xref_obj2 + 1;
    let mut entries: Vec<(u64, Entry)> = Vec::new();
    let mut packed: Vec<(u64, String)> = Vec::new();
    // root replaced: the old kids plus the new level-1 nodes
    let mut root_kids = l1_kids.clone();
    root_kids.extend((0..a2).map(|i| l1_base2 + i));
    packed.push((2, pages_node_root(&root_kids, all_pages)));
    for a in 0..a2 {
        let first = a * GROUP;
        let last = ((a + 1) * GROUP).min(g2);
        let kids: Vec<u64> = (first..last).map(|g| l2_base2 + g).collect();
        let count = (first * GROUP..(last * GROUP).min(plan.p2)).count() as u64;
        packed.push((l1_base2 + a, pages_node(2, &kids, count)));
    }
    for g in 0..g2 {
        let first = g * GROUP;
        let last = ((g + 1) * GROUP).min(plan.p2);
        let kids: Vec<u64> = (first..last).map(|k| page_base2 + 3 * k).collect();
        let parent = l1_base2 + g / GROUP;
        packed.push((l2_base2 + g, pages_node(parent, &kids, last - first)));
    }
    for k in 0..plan.p2 {
        let num = page_base2 + 3 * k;
        let page_index = plan.p1 + k;
        let text = page_text(page_index, all_pages, &mut rng);
        let line2 = format!("revision 2 object {num}");
        rng.fill(&mut image);
        let parent = l2_base2 + k / GROUP;
        packed.push((num, page_dict(parent, num + 1, num + 2)));
        let at = w.stream(num + 1, "", &content_stream(&text, &line2, plan.image_w, plan.image_h))?;
        entries.push((num + 1, Entry::Plain(at)));
        let at = w.stream(
            num + 2,
            &format!(
                "/Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB /BitsPerComponent 8",
                plan.image_w, plan.image_h
            ),
            &image,
        )?;
        entries.push((num + 2, Entry::Plain(at)));
        if k == plan.p2 - 1 {
            samples.push((page_index, text));
        }
    }
    packed.sort_by_key(|(num, _)| *num);
    let mut stream_number = stm_base2;
    let mut written_streams = 0u64;
    for chunk in packed.chunks(OBJSTM_MAX) {
        let (data, first) = object_stream(chunk);
        let at = w.stream(
            stream_number,
            &format!("/Type /ObjStm /N {} /First {first} /Filter /FlateDecode", chunk.len()),
            &data,
        )?;
        entries.push((stream_number, Entry::Plain(at)));
        for (index, (num, _)) in chunk.iter().enumerate() {
            entries.push((*num, Entry::Packed { stream: stream_number, index: index as u16 }));
        }
        stream_number += 1;
        written_streams += 1;
    }
    let xref2 = w.file.position();
    entries.push((xref_obj2, Entry::Plain(xref2)));
    entries.sort_by_key(|(num, _)| *num);
    let data = zlib_stored(&xref_stream_data(&entries));
    w.stream(
        xref_obj2,
        &format!(
            "/Type /XRef /Size {n2} /W [1 8 2] /Index {} /Root 1 0 R /Info 4 0 R /Prev {xref1} /ID [<{id}> <{id}>] /Filter /FlateDecode",
            index_array(&entries)
        ),
        &data,
    )?;
    w.file.write_all(format!("startxref\n{xref2}\n%%EOF\n").as_bytes())?;
    revisions.push(RevisionFacts {
        kind: "xref-stream".into(),
        start: r2_start,
        end: w.file.position(),
        startxref: xref2,
        objects_after: n2,
        object_streams: written_streams,
    });

    // ---------------------------------------------------------------- revision 3
    let r3_start = w.file.position();
    let embedded = n2;
    let filespec = n2 + 1;
    let stm3 = n2 + 2;
    let xref_obj3 = n2 + 3;
    let n3 = n2 + 4;
    let catalog3 = format!(
        "<< /Type /Catalog /Pages 2 0 R /Lang (kk-KZ) /ViewerPreferences << /DisplayDocTitle true >> /Names << /EmbeddedFiles << /Names [(proof-payload.bin) {filespec} 0 R] >> >> /AF [{filespec} 0 R] >>"
    );
    let (stm_data, first) = object_stream(&[(1, catalog3)]);
    let filespec_text = format!(
        "<< /Type /Filespec /F (proof-payload.bin) /UF (proof-payload.bin) /AFRelationship /Data /EF << /F {embedded} 0 R /UF {embedded} 0 R >> >>"
    );
    // The embedded file is sized last, from the exact length of everything around it.
    let head = |len: u64| format!("{embedded} 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream /Params << /Size {len} >> /Length {len} >>\nstream\n");
    let stream_tail = b"\nendstream\nendobj\n";
    let mut payload_len = 1u64 << 20;
    let tail_for = |payload_len: u64, at: u64| -> std::io::Result<(Vec<u8>, u64)> {
        let embedded_at = at;
        let base = at + head(payload_len).len() as u64 + payload_len + stream_tail.len() as u64;
        let mut out: Vec<u8> = Vec::new();
        let filespec_at = base;
        write!(out, "{filespec} 0 obj\n{filespec_text}\nendobj\n")?;
        let stm_at = base + out.len() as u64;
        write!(
            out,
            "{stm3} 0 obj\n<< /Type /ObjStm /N 1 /First {first} /Filter /FlateDecode /Length {} >>\nstream\n",
            stm_data.len()
        )?;
        out.extend_from_slice(&stm_data);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        let xref_at = base + out.len() as u64;
        let entries3 = [
            (1, Entry::Packed { stream: stm3, index: 0 }),
            (embedded, Entry::Plain(embedded_at)),
            (filespec, Entry::Plain(filespec_at)),
            (stm3, Entry::Plain(stm_at)),
            (xref_obj3, Entry::Plain(xref_at)),
        ];
        let xdata = zlib_stored(&xref_stream_data(&entries3));
        write!(
            out,
            "{xref_obj3} 0 obj\n<< /Type /XRef /Size {n3} /W [1 8 2] /Index {} /Root 1 0 R /Info 4 0 R /Prev {xref2} /ID [<{id}> <{id}>] /Filter /FlateDecode /Length {} >>\nstream\n",
            index_array(&entries3),
            xdata.len()
        )?;
        out.extend_from_slice(&xdata);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        write!(out, "startxref\n{xref_at}\n%%EOF\n")?;
        Ok((out, xref_at))
    };
    let at = w.file.position();
    let mut stable = false;
    for _ in 0..8 {
        let (tail, _) = tail_for(payload_len, at)?;
        let used = at + head(payload_len).len() as u64 + payload_len + stream_tail.len() as u64 + tail.len() as u64;
        if used == total {
            stable = true;
            break;
        }
        payload_len = (payload_len as i128 + (total as i128 - used as i128)) as u64;
    }
    assert!(stable, "the embedded file length converges");
    let (tail, xref3) = tail_for(payload_len, at)?;
    w.file.write_all(head(payload_len).as_bytes())?;
    let embedded_offset = w.file.position();
    let mut sha = Sha256::new();
    let mut remaining = payload_len;
    let mut buffer = vec![0u8; 1 << 20];
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        rng.fill(&mut buffer[..take]);
        w.file.write_all(&buffer[..take])?;
        sha.update(&buffer[..take]);
        remaining -= take as u64;
    }
    w.file.write_all(stream_tail)?;
    w.file.write_all(&tail)?;
    revisions.push(RevisionFacts {
        kind: "xref-stream".into(),
        start: r3_start,
        end: w.file.position(),
        startxref: xref3,
        objects_after: n3,
        object_streams: 1,
    });
    drop(w);
    let digests = file.finish()?;
    assert_eq!(digests.len, total, "the proof PDF must have the exact size");
    Ok((
        PdfFacts {
            profile,
            pages: all_pages,
            revisions,
            embedded_offset,
            embedded_len: payload_len,
            embedded_sha256: super::hex(&sha.finalize()),
            samples,
            final_startxref: xref3,
        },
        digests,
    ))
}

fn pages_node_root(kids: &[u64], count: u64) -> String {
    let mut s = String::from("<< /Type /Pages /Kids [");
    for (i, k) in kids.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{k} 0 R"));
    }
    s.push_str(&format!("] /Count {count} >>"));
    s
}
