//! A minimal reader of Java class files (JVMS §4.1–4.7): the class, its members with their
//! annotation types, and the string and integer constants. Every index and length is checked;
//! other attributes are skipped by their length.

use std::fmt;

/// Largest class file read.
pub const CLASS_MAX: usize = 16 << 20;

/// A class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassInfo {
    /// Internal name (`a/b/C`).
    pub name: String,
    /// Access flags.
    pub access: u16,
    /// Superclass, internal name.
    pub super_name: Option<String>,
    /// Interfaces, internal names.
    pub interfaces: Vec<String>,
    /// Fields.
    pub fields: Vec<Member>,
    /// Methods.
    pub methods: Vec<Member>,
    /// `CONSTANT_String` values.
    pub strings: Vec<String>,
    /// `CONSTANT_Integer` values.
    pub ints: Vec<i32>,
}

/// A field or method.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Member {
    /// Access flags.
    pub access: u16,
    /// Name.
    pub name: String,
    /// Descriptor.
    pub descriptor: String,
    /// Descriptors of its annotation types (visible and invisible).
    pub annotations: Vec<String>,
}

/// Why a class file does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassError(pub String);

impl fmt::Display for ClassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "class file: {}", self.0)
    }
}

impl std::error::Error for ClassError {}

/// `ACC_PUBLIC`.
pub const ACC_PUBLIC: u16 = 0x0001;
/// `ACC_PROTECTED`.
pub const ACC_PROTECTED: u16 = 0x0004;
/// `ACC_INTERFACE`.
pub const ACC_INTERFACE: u16 = 0x0200;
/// `ACC_SYNTHETIC`.
pub const ACC_SYNTHETIC: u16 = 0x1000;
/// `ACC_ANNOTATION`.
pub const ACC_ANNOTATION: u16 = 0x2000;
/// `ACC_ENUM`.
pub const ACC_ENUM: u16 = 0x4000;

#[derive(Clone, Debug)]
enum Constant {
    Utf8(String),
    Integer(i32),
    Class(u16),
    String(u16),
    Other,
    /// The unusable slot after a long or double.
    Gap,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ClassError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| ClassError("truncated".to_owned()))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ClassError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ClassError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ClassError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Parses a class file.
///
/// # Errors
///
/// [`ClassError`] for anything invalid: never a panic.
pub fn parse_class(bytes: &[u8]) -> Result<ClassInfo, ClassError> {
    if bytes.len() > CLASS_MAX {
        return Err(ClassError("too large".to_owned()));
    }
    let mut r = Reader {
        data: bytes,
        pos: 0,
    };
    if r.u32()? != 0xCAFE_BABE {
        return Err(ClassError("no CAFEBABE".to_owned()));
    }
    r.take(4)?; // minor, major
    let count = r.u16()?;
    let mut pool = vec![Constant::Gap];
    while pool.len() < usize::from(count) {
        let tag = r.u8()?;
        let c = match tag {
            1 => {
                let len = r.u16()?;
                Constant::Utf8(modified_utf8(r.take(usize::from(len))?)?)
            }
            3 => Constant::Integer(r.u32()? as i32),
            4 => {
                r.take(4)?;
                Constant::Other
            }
            5 | 6 => {
                r.take(8)?;
                pool.push(Constant::Other);
                Constant::Gap
            }
            7 => Constant::Class(r.u16()?),
            8 => Constant::String(r.u16()?),
            9..=12 | 17 | 18 => {
                r.take(4)?;
                Constant::Other
            }
            15 => {
                r.take(3)?;
                Constant::Other
            }
            16 | 19 | 20 => {
                r.take(2)?;
                Constant::Other
            }
            t => return Err(ClassError(format!("constant tag {t}"))),
        };
        pool.push(c);
    }
    if pool.len() != usize::from(count) {
        return Err(ClassError("constant pool overruns its count".to_owned()));
    }
    let utf8 = |i: u16| match pool.get(usize::from(i)) {
        Some(Constant::Utf8(s)) => Ok(s.clone()),
        _ => Err(ClassError(format!("index {i} is not Utf8"))),
    };
    let class = |i: u16| match pool.get(usize::from(i)) {
        Some(Constant::Class(n)) => utf8(*n),
        _ => Err(ClassError(format!("index {i} is not Class"))),
    };
    let access = r.u16()?;
    let name = class(r.u16()?)?;
    let super_name = match r.u16()? {
        0 => None,
        i => Some(class(i)?),
    };
    let interfaces = (0..r.u16()?)
        .map(|_| class(r.u16()?))
        .collect::<Result<Vec<_>, _>>()?;
    let members = |r: &mut Reader<'_>| -> Result<Vec<Member>, ClassError> {
        let n = r.u16()?;
        let mut out = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let access = r.u16()?;
            let name = utf8(r.u16()?)?;
            let descriptor = utf8(r.u16()?)?;
            let mut annotations = Vec::new();
            for _ in 0..r.u16()? {
                let attr = utf8(r.u16()?)?;
                let len = r.u32()? as usize;
                let body = r.take(len)?;
                if attr == "RuntimeVisibleAnnotations" || attr == "RuntimeInvisibleAnnotations" {
                    let mut a = Reader { data: body, pos: 0 };
                    for _ in 0..a.u16()? {
                        annotations.push(annotation(&mut a, &utf8)?);
                    }
                }
            }
            out.push(Member {
                access,
                name,
                descriptor,
                annotations,
            });
        }
        Ok(out)
    };
    let fields = members(&mut r)?;
    let methods = members(&mut r)?;
    for _ in 0..r.u16()? {
        r.u16()?;
        let len = r.u32()? as usize;
        r.take(len)?;
    }
    let mut strings = Vec::new();
    let mut ints = Vec::new();
    for c in &pool {
        match c {
            Constant::String(i) => strings.push(utf8(*i)?),
            Constant::Integer(v) => ints.push(*v),
            _ => {}
        }
    }
    Ok(ClassInfo {
        name,
        access,
        super_name,
        interfaces,
        fields,
        methods,
        strings,
        ints,
    })
}

/// One `annotation`: its type descriptor; the element values are skipped.
fn annotation(
    r: &mut Reader<'_>,
    utf8: &dyn Fn(u16) -> Result<String, ClassError>,
) -> Result<String, ClassError> {
    let ty = utf8(r.u16()?)?;
    for _ in 0..r.u16()? {
        r.u16()?;
        element_value(r, utf8, 0)?;
    }
    Ok(ty)
}

fn element_value(
    r: &mut Reader<'_>,
    utf8: &dyn Fn(u16) -> Result<String, ClassError>,
    depth: u32,
) -> Result<(), ClassError> {
    if depth > 64 {
        return Err(ClassError("annotation nesting".to_owned()));
    }
    match r.u8()? {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b's' | b'c' => {
            r.u16()?;
        }
        b'e' => {
            r.u16()?;
            r.u16()?;
        }
        b'@' => {
            utf8(r.u16()?)?;
            for _ in 0..r.u16()? {
                r.u16()?;
                element_value(r, utf8, depth + 1)?;
            }
        }
        b'[' => {
            for _ in 0..r.u16()? {
                element_value(r, utf8, depth + 1)?;
            }
        }
        t => return Err(ClassError(format!("element value tag {t}"))),
    }
    Ok(())
}

/// Java's modified UTF-8 (JVMS §4.4.7): NUL as `C0 80`, supplementary characters as
/// surrogate pairs; unpaired surrogates become U+FFFD.
fn modified_utf8(bytes: &[u8]) -> Result<String, ClassError> {
    let bad = || ClassError("invalid modified UTF-8".to_owned());
    let cont = |b: Option<&u8>| match b {
        Some(&b) if b & 0xC0 == 0x80 => Ok(u16::from(b & 0x3F)),
        _ => Err(bad()),
    };
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let unit = match b {
            0x01..=0x7F => {
                i += 1;
                u16::from(b)
            }
            0xC0..=0xDF => {
                let u = (u16::from(b & 0x1F) << 6) | cont(bytes.get(i + 1))?;
                i += 2;
                u
            }
            0xE0..=0xEF => {
                let u = (u16::from(b & 0x0F) << 12)
                    | (cont(bytes.get(i + 1))? << 6)
                    | cont(bytes.get(i + 2))?;
                i += 3;
                u
            }
            _ => return Err(bad()),
        };
        units.push(unit);
    }
    Ok(String::from_utf16_lossy(&units))
}
