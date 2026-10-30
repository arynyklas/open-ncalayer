//! `visualCMS`'s report: A4 pages in Source Sans Pro Light — the heading «Информация об
//! электронном документе», then for each signer «N) ПОДПИСАНТ - <name>» and a two-column
//! table (ИИН, ФИО, serial number, validity, signing time) — appended to the signed PDF
//! after its own pages. The same text and layout as the original's, not its bytes: the
//! pages are added by an incremental update, the document's bytes kept as they are.

use crate::pdf::{self, Dict, Document, Obj, Update, get, name, set};
use crate::ttf::Font;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::collections::BTreeMap;
use std::io::Write;

/// The font of the report (SIL Open Font License 1.1, `fonts/OFL.txt`).
const FONT: &[u8] = include_bytes!("../fonts/SourceSansPro-Light.ttf");

/// Its PostScript name.
const FONT_NAME: &str = "SourceSansPro-Light";

/// A4, in points.
const PAGE: (f32, f32) = (595.0, 842.0);
/// The page margins.
const MARGIN: f32 = 36.0;
/// The text size (iText's default, the heading's too).
const SIZE: f32 = 12.0;
/// Lines of a paragraph, as a multiple of its size.
const LEADING: f32 = 1.35;
/// The table's column widths, proportions of the text width.
const COLUMNS: (f32, f32) = (472.0, 682.0);
/// A cell's padding.
const PADDING: f32 = 2.0;
/// A cell's border.
const BORDER: f32 = 0.5;
/// Space above each signer.
const GAP: f32 = 8.0;

/// One signer of the report.
pub(crate) struct Signer {
    pub(crate) name: String,
    pub(crate) iin: String,
    pub(crate) serial: String,
    pub(crate) period: String,
    pub(crate) signed_at: String,
}

/// The rows of a signer's table: the label (followed by a tab in the original, which
/// lays out as space) and the value.
fn rows(signer: &Signer) -> [(&'static str, &str); 5] {
    [
        ("ИИН", &signer.iin),
        ("ФИО", &signer.name),
        ("Серийный номер сертификата", &signer.serial),
        ("Срок действия сертификата", &signer.period),
        ("Дата подписания", &signer.signed_at),
    ]
}

/// The pages being laid out: their content streams, and the glyphs they use.
struct Writer<'f> {
    font: &'f Font<'f>,
    pages: Vec<Vec<u8>>,
    /// The top of the free space of the last page.
    y: f32,
    glyphs: BTreeMap<u16, char>,
}

impl<'f> Writer<'f> {
    fn new(font: &'f Font<'f>) -> Writer<'f> {
        let mut writer = Writer {
            font,
            pages: Vec::new(),
            y: 0.0,
            glyphs: BTreeMap::new(),
        };
        writer.new_page();
        writer
    }

    fn new_page(&mut self) {
        self.pages.push(Vec::new());
        self.y = PAGE.1 - MARGIN;
    }

    /// Starts a new page unless `height` fits on this one (an empty page takes anything).
    fn ensure(&mut self, height: f32) {
        if self.y - height < MARGIN && self.y < PAGE.1 - MARGIN {
            self.new_page();
        }
    }

    fn content(&mut self) -> &mut Vec<u8> {
        self.pages.last_mut().expect("a page")
    }

    /// `text` at (`x`, `baseline`), simulated bold if `bold`.
    fn text(&mut self, text: &str, x: f32, baseline: f32, size: f32, bold: bool) {
        let mut hex = String::new();
        for c in text.chars() {
            let glyph = self.font.glyph(c);
            self.glyphs.entry(glyph).or_insert(c);
            hex.push_str(&format!("{glyph:04X}"));
        }
        // Bold: fill and stroke, as iText makes a bold of a font without one; the text
        // render mode is state that outlives ET, so it is set back to fill after the text.
        let (bold_on, bold_off) = if bold {
            (format!("2 Tr {:.2} w ", size / 30.0), " 0 Tr")
        } else {
            (String::new(), "")
        };
        let op =
            format!("BT /F1 {size} Tf {bold_on}{x:.2} {baseline:.2} Td <{hex}> Tj{bold_off} ET\n");
        self.content().extend(op.as_bytes());
    }

    /// A paragraph of `text` across the text width.
    fn paragraph(&mut self, text: &str, size: f32, bold: bool) {
        let lines = wrap(self.font, text, size, PAGE.0 - 2.0 * MARGIN);
        for line in lines {
            let height = size * LEADING;
            self.ensure(height);
            let baseline = self.y - size;
            self.text(&line, MARGIN, baseline, size, bold);
            self.y -= height;
        }
    }

    /// A table row of two cells.
    fn row(&mut self, label: &str, value: &str) {
        let width = PAGE.0 - 2.0 * MARGIN;
        let first = width * COLUMNS.0 / (COLUMNS.0 + COLUMNS.1);
        let second = width - first;
        let inner = |w: f32| w - 2.0 * PADDING - BORDER;
        let left = wrap(self.font, label, SIZE, inner(first));
        let right = wrap(self.font, value, SIZE, inner(second));
        let lines = left.len().max(right.len()).max(1);
        let height = lines as f32 * SIZE * LEADING + 2.0 * PADDING;
        self.ensure(height);
        let top = self.y;
        for (column, x, w) in [(left, MARGIN, first), (right, MARGIN + first, second)] {
            let border = format!(
                "{BORDER} w {x:.2} {:.2} {w:.2} {height:.2} re S\n",
                top - height
            );
            self.content().extend(border.as_bytes());
            for (i, line) in column.iter().enumerate() {
                let baseline = top - PADDING - SIZE - i as f32 * SIZE * LEADING;
                self.text(line, x + PADDING + BORDER, baseline, SIZE, false);
            }
        }
        self.y -= height;
    }
}

/// `text` in lines no wider than `width`: by words, a word too wide by characters.
fn wrap(font: &Font, text: &str, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ') {
        let candidate = if line.is_empty() {
            word.to_owned()
        } else {
            format!("{line} {word}")
        };
        if font.width(&candidate, size) <= width {
            line = candidate;
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        for c in word.chars() {
            let longer = format!("{line}{c}");
            if !line.is_empty() && font.width(&longer, size) > width {
                lines.push(std::mem::take(&mut line));
                line.push(c);
            } else {
                line = longer;
            }
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// The report pages of `signers`: their content streams and the glyphs they use.
fn lay_out(font: &Font, signers: &[Signer]) -> (Vec<Vec<u8>>, BTreeMap<u16, char>) {
    let mut writer = Writer::new(font);
    writer.paragraph("Информация об электронном документе", SIZE, true);
    for (i, signer) in signers.iter().enumerate() {
        // The heading stays with the first row of its table.
        writer.ensure(GAP + SIZE * LEADING * 2.0 + 2.0 * PADDING);
        writer.y -= GAP;
        writer.paragraph(
            &format!("{}) ПОДПИСАНТ - {}", i + 1, signer.name),
            SIZE,
            true,
        );
        for (label, value) in rows(signer) {
            writer.row(label, value);
        }
    }
    (writer.pages, writer.glyphs)
}

/// The ToUnicode CMap of `glyphs`.
fn to_unicode(glyphs: &BTreeMap<u16, char>) -> Vec<u8> {
    let mut cmap = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
         1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<(&u16, &char)> = glyphs.iter().filter(|(g, _)| **g != 0).collect();
    for chunk in entries.chunks(100) {
        cmap.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (glyph, c) in chunk {
            let mut units = [0u16; 2];
            let hex: String = c
                .encode_utf16(&mut units)
                .iter()
                .map(|u| format!("{u:04X}"))
                .collect();
            cmap.push_str(&format!("<{glyph:04X}> <{hex}>\n"));
        }
        cmap.push_str("endbfchar\n");
    }
    cmap.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    cmap.into_bytes()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).expect("in memory");
    encoder.finish().expect("in memory")
}

fn int(i: i32) -> Obj {
    Obj::Int(i64::from(i))
}

fn real(f: f32) -> Obj {
    Obj::Real(format!("{f:.2}"))
}

fn dict(entries: Vec<(&str, Obj)>) -> Dict {
    entries
        .into_iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v))
        .collect()
}

/// The font's objects in `update`: the Type0 font's number.
fn put_font(
    update: &mut Update,
    font: &Font,
    glyphs: &BTreeMap<u16, char>,
) -> Result<u32, pdf::Error> {
    let type0 = update.reserve()?;
    let cid = update.reserve()?;
    let descriptor = update.reserve()?;
    let file = update.reserve()?;
    let cmap = update.reserve()?;
    update.put(
        file,
        Obj::Stream(
            dict(vec![
                ("Length1", Obj::Int(font.data().len() as i64)),
                ("Filter", name("FlateDecode")),
            ]),
            zlib(font.data()),
        ),
    );
    let [x0, y0, x1, y1] = font.bbox.map(|v| int(font.scale(i32::from(v))));
    update.put(
        descriptor,
        Obj::Dict(dict(vec![
            ("Type", name("FontDescriptor")),
            ("FontName", name(FONT_NAME)),
            ("Flags", Obj::Int(32)),
            ("FontBBox", Obj::Array(vec![x0, y0, x1, y1])),
            ("ItalicAngle", real(font.italic_angle)),
            ("Ascent", int(font.scale(i32::from(font.ascent)))),
            ("Descent", int(font.scale(i32::from(font.descent)))),
            ("CapHeight", int(font.scale(i32::from(font.cap_height)))),
            ("StemV", Obj::Int(80)),
            ("FontFile2", Obj::Ref(file, 0)),
        ])),
    );
    let mut widths = Vec::new();
    for glyph in glyphs.keys() {
        widths.push(int(i32::from(*glyph)));
        widths.push(Obj::Array(vec![int(font.advance(*glyph))]));
    }
    update.put(
        cid,
        Obj::Dict(dict(vec![
            ("Type", name("Font")),
            ("Subtype", name("CIDFontType2")),
            ("BaseFont", name(FONT_NAME)),
            (
                "CIDSystemInfo",
                Obj::Dict(dict(vec![
                    ("Registry", Obj::Str(b"Adobe".to_vec())),
                    ("Ordering", Obj::Str(b"Identity".to_vec())),
                    ("Supplement", Obj::Int(0)),
                ])),
            ),
            ("FontDescriptor", Obj::Ref(descriptor, 0)),
            ("DW", Obj::Int(1000)),
            ("W", Obj::Array(widths)),
            ("CIDToGIDMap", name("Identity")),
        ])),
    );
    update.put(cmap, Obj::Stream(Vec::new(), to_unicode(glyphs)));
    update.put(
        type0,
        Obj::Dict(dict(vec![
            ("Type", name("Font")),
            ("Subtype", name("Type0")),
            ("BaseFont", name(FONT_NAME)),
            ("Encoding", name("Identity-H")),
            ("DescendantFonts", Obj::Array(vec![Obj::Ref(cid, 0)])),
            ("ToUnicode", Obj::Ref(cmap, 0)),
        ])),
    );
    Ok(type0)
}

/// `pdf` with the report of `signers` after its pages.
///
/// # Errors
///
/// `pdf` is not a PDF this reader can extend (no page tree, encrypted, filters other
/// than Flate in its cross-reference streams).
pub(crate) fn append(pdf: &[u8], signers: &[Signer]) -> Result<Vec<u8>, pdf::Error> {
    let font = Font::read(FONT).ok_or("the font does not read")?;
    let doc = Document::read(pdf)?;
    let root = get(&doc.trailer, "Root").ok_or("no Root")?;
    let Obj::Dict(catalog) = doc.resolve(root)? else {
        return Err("no catalog");
    };
    let Some(&Obj::Ref(pages_num, pages_gen)) = get(&catalog, "Pages") else {
        return Err("no page tree");
    };
    let Obj::Dict(mut pages) = doc.object(pages_num)? else {
        return Err("no page tree");
    };
    let Obj::Array(mut kids) = doc.resolve(get(&pages, "Kids").ok_or("no Kids")?)? else {
        return Err("bad Kids");
    };
    let Obj::Int(count) = doc.resolve(get(&pages, "Count").ok_or("no Count")?)? else {
        return Err("bad Count");
    };

    let (contents, glyphs) = lay_out(&font, signers);
    let mut update = Update::new(&doc)?;
    let type0 = put_font(&mut update, &font, &glyphs)?;
    let media_box = Obj::Array(vec![
        Obj::Int(0),
        Obj::Int(0),
        Obj::Int(PAGE.0 as i64),
        Obj::Int(PAGE.1 as i64),
    ]);
    for content in &contents {
        let page = update.reserve()?;
        let stream = update.reserve()?;
        update.put(stream, Obj::Stream(Vec::new(), content.clone()));
        update.put(
            page,
            Obj::Dict(dict(vec![
                ("Type", name("Page")),
                ("Parent", Obj::Ref(pages_num, pages_gen)),
                // Nothing inherited from the document's page tree.
                ("MediaBox", media_box.clone()),
                ("CropBox", media_box.clone()),
                ("Rotate", Obj::Int(0)),
                (
                    "Resources",
                    Obj::Dict(dict(vec![(
                        "Font",
                        Obj::Dict(dict(vec![("F1", Obj::Ref(type0, 0))])),
                    )])),
                ),
                ("Contents", Obj::Ref(stream, 0)),
            ])),
        );
        kids.push(Obj::Ref(page, 0));
    }
    let count = i64::try_from(contents.len())
        .ok()
        .and_then(|added| count.checked_add(added))
        .ok_or("bad Count")?;
    set(&mut pages, "Kids", Obj::Array(kids));
    set(&mut pages, "Count", Obj::Int(count));
    update.put(pages_num, Obj::Dict(pages));
    update.finish()
}
