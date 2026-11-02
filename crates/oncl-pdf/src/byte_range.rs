use crate::{PdfError, Result};
use std::ops::Range;

/// Two ordered signed regions, excluding precisely one signature Contents token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange(pub(crate) [u64; 4]);
impl ByteRange {
    pub fn new(values: [u64; 4], extent: u64) -> Result<Self> {
        let [start, first, second, last] = values;
        if start != 0 || first >= second || second.checked_add(last).is_none_or(|end| end > extent)
        {
            return Err(PdfError::Malformed("invalid ByteRange"));
        }
        Ok(Self(values))
    }
    pub fn values(self) -> [u64; 4] {
        self.0
    }
    pub fn signed_end(self) -> u64 {
        self.0[2] + self.0[3]
    }
    pub fn gap(self) -> Range<u64> {
        self.0[1]..self.0[2]
    }
}
