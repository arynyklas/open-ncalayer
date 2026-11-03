use crate::{PdfError, Result};
use oncl_pki::{io::Source, resource::ResourceScope};
use std::io::SeekFrom;

pub(crate) struct Input<'a> {
    pub source: Source<'a>,
    pub base: u64,
    pub extent: u64,
}
impl<'a> Input<'a> {
    pub fn new(mut source: Source<'a>, scope: &ResourceScope) -> Result<Self> {
        scope.checkpoint()?;
        let reader = source
            .as_seekable()
            .ok_or(PdfError::Unsupported("seekable source required"))?;
        let base = reader.stream_position()?;
        let end = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(base))?;
        let extent = end
            .checked_sub(base)
            .ok_or(PdfError::Malformed("source extent"))?;
        if !source.is_snapshot_for(scope)? {
            scope.account_input(extent)?;
        }
        Ok(Self {
            source,
            base,
            extent,
        })
    }
    pub fn read_at(&mut self, offset: u64, size: usize, scope: &ResourceScope) -> Result<Vec<u8>> {
        scope.checkpoint()?;
        if offset > self.extent {
            return Err(PdfError::Malformed("offset outside source"));
        }
        let size = (self.extent - offset).min(size as u64) as usize;
        let reader = self
            .source
            .as_seekable()
            .ok_or(PdfError::Unsupported("seekable source required"))?;
        reader.seek(SeekFrom::Start(
            self.base
                .checked_add(offset)
                .ok_or(PdfError::Malformed("offset overflow"))?,
        ))?;
        let mut bytes = vec![0; size];
        reader.read_exact(&mut bytes)?;
        scope.checkpoint()?;
        Ok(bytes)
    }
}
