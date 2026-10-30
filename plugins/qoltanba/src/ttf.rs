//! What the report needs of its TrueType font: glyphs of characters, their advance widths
//! and the font's metrics for the PDF font descriptor.

/// A TrueType font, read.
pub(crate) struct Font<'a> {
    data: &'a [u8],
    /// Font units per em.
    units_per_em: u16,
    /// `head`: xMin, yMin, xMax, yMax.
    pub(crate) bbox: [i16; 4],
    /// `hhea`: ascender and descender.
    pub(crate) ascent: i16,
    pub(crate) descent: i16,
    /// `OS/2` sCapHeight (the ascender without one).
    pub(crate) cap_height: i16,
    /// `post` italicAngle, in degrees.
    pub(crate) italic_angle: f32,
    hmtx: &'a [u8],
    number_of_h_metrics: u16,
    /// The `cmap` subtable of format 4 (Unicode BMP).
    cmap4: &'a [u8],
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn i16_at(data: &[u8], at: usize) -> Option<i16> {
    Some(i16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> Font<'a> {
    /// The font in `data`; `None` if it lacks a table the report needs.
    pub(crate) fn read(data: &'a [u8]) -> Option<Font<'a>> {
        let tables = u16_at(data, 4)?;
        let table = |tag: &[u8; 4]| -> Option<&'a [u8]> {
            (0..usize::from(tables)).find_map(|i| {
                let record = 12 + 16 * i;
                if data.get(record..record + 4)? != tag {
                    return None;
                }
                let offset = u32_at(data, record + 8)? as usize;
                let len = u32_at(data, record + 12)? as usize;
                data.get(offset..offset.checked_add(len)?)
            })
        };
        let head = table(b"head")?;
        let hhea = table(b"hhea")?;
        let ascent = i16_at(hhea, 4)?;
        let cap_height = table(b"OS/2")
            .filter(|os2| u16_at(os2, 0).is_some_and(|version| version >= 2))
            .and_then(|os2| i16_at(os2, 88))
            .unwrap_or(ascent);
        let italic_angle = table(b"post")
            .and_then(|post| u32_at(post, 4))
            .map_or(0.0, |fixed| fixed as i32 as f32 / 65536.0);
        let cmap = table(b"cmap")?;
        let cmap4 = (0..usize::from(u16_at(cmap, 2)?)).find_map(|i| {
            let record = 4 + 8 * i;
            let platform = u16_at(cmap, record)?;
            let encoding = u16_at(cmap, record + 2)?;
            let offset = u32_at(cmap, record + 4)? as usize;
            let sub = cmap.get(offset..)?;
            let unicode = (platform == 3 && encoding == 1) || platform == 0;
            (unicode && u16_at(sub, 0)? == 4).then(|| {
                let len = usize::from(u16_at(sub, 2).unwrap_or(0));
                &sub[..len.min(sub.len())]
            })
        })?;
        Some(Font {
            data,
            units_per_em: u16_at(head, 18)?,
            bbox: [
                i16_at(head, 36)?,
                i16_at(head, 38)?,
                i16_at(head, 40)?,
                i16_at(head, 42)?,
            ],
            ascent,
            descent: i16_at(hhea, 6)?,
            cap_height,
            italic_angle,
            hmtx: table(b"hmtx")?,
            number_of_h_metrics: u16_at(hhea, 34)?,
            cmap4,
        })
    }

    /// The font file.
    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    /// `units` of the font in thousandths of the em (PDF glyph space).
    pub(crate) fn scale(&self, units: i32) -> i32 {
        units * 1000 / i32::from(self.units_per_em)
    }

    /// The glyph of `c`, 0 (`.notdef`) for a character the font lacks.
    pub(crate) fn glyph(&self, c: char) -> u16 {
        let Ok(code) = u16::try_from(u32::from(c)) else {
            return 0;
        };
        self.lookup(code).unwrap_or(0)
    }

    fn lookup(&self, code: u16) -> Option<u16> {
        let t = self.cmap4;
        let segments = usize::from(u16_at(t, 6)? / 2);
        let ends = 14;
        let starts = ends + 2 * segments + 2;
        let deltas = starts + 2 * segments;
        let range_offsets = deltas + 2 * segments;
        for i in 0..segments {
            if code > u16_at(t, ends + 2 * i)? {
                continue;
            }
            let start = u16_at(t, starts + 2 * i)?;
            if code < start {
                return None;
            }
            let delta = u16_at(t, deltas + 2 * i)?;
            let range_offset = usize::from(u16_at(t, range_offsets + 2 * i)?);
            if range_offset == 0 {
                return Some(code.wrapping_add(delta));
            }
            let at = range_offsets + 2 * i + range_offset + 2 * usize::from(code - start);
            let glyph = u16_at(t, at)?;
            return Some(if glyph == 0 {
                0
            } else {
                glyph.wrapping_add(delta)
            });
        }
        None
    }

    /// The advance width of `glyph`, in thousandths of the em.
    pub(crate) fn advance(&self, glyph: u16) -> i32 {
        let index = glyph.min(self.number_of_h_metrics.saturating_sub(1));
        let units = u16_at(self.hmtx, 4 * usize::from(index)).unwrap_or(0);
        self.scale(i32::from(units))
    }

    /// The width of `text` at `size` points.
    pub(crate) fn width(&self, text: &str, size: f32) -> f32 {
        let thousandths: i32 = text.chars().map(|c| self.advance(self.glyph(c))).sum();
        thousandths as f32 * size / 1000.0
    }
}
