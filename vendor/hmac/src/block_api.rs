use crate::utils::{IPAD, OPAD, ByteGuard, derive_key_into, get_der_key};
use core::{fmt, slice};
use digest::{
    InvalidLength, KeyInit, MacMarker, Output, Reset,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, EagerHash, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    block_buffer::Eager,
    common::{Key, KeySizeUser},
};

/// Existing upstream HMAC core, preserving non-generic mode inference.
pub type HmacCore<D> = HmacCoreMode<D, false>;

/// Shared HMAC core with compile-time scratch cleanup selection.
/// Secret mode requires a digest whose own state/scratch is secret-safe.
pub struct HmacCoreMode<D: EagerHash, const SECRET: bool> {
    digest: D::Core,
    opad_digest: D::Core,
}

impl<D: EagerHash, const SECRET: bool> HmacCoreMode<D, SECRET> {
    pub(crate) fn unkeyed() -> Self {
        Self { digest: D::Core::default(), opad_digest: D::Core::default() }
    }
    pub(crate) fn initialize_key_in_place(&mut self, key: &[u8]) {
        let mut storage = Block::<D>::default();
        let mut buf = ByteGuard::<_, SECRET>::new(&mut storage);
        derive_key_into::<D, SECRET>(key, &mut buf);
        buf.iter_mut().for_each(|b| *b ^= IPAD);
        self.digest.update_blocks(slice::from_ref(&*buf));
        buf.iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);
        self.opad_digest.update_blocks(slice::from_ref(&*buf));
    }
}

impl<D: EagerHash, const SECRET: bool> Clone for HmacCoreMode<D, SECRET> {
    fn clone(&self) -> Self {
        Self { digest: self.digest.clone(), opad_digest: self.opad_digest.clone() }
    }
}
impl<D: EagerHash, const SECRET: bool> MacMarker for HmacCoreMode<D, SECRET> {}
impl<D: EagerHash, const SECRET: bool> BufferKindUser for HmacCoreMode<D, SECRET> {
    type BufferKind = Eager;
}
impl<D: EagerHash, const SECRET: bool> KeySizeUser for HmacCoreMode<D, SECRET> {
    type KeySize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}
impl<D: EagerHash, const SECRET: bool> BlockSizeUser for HmacCoreMode<D, SECRET> {
    type BlockSize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}
impl<D: EagerHash, const SECRET: bool> OutputSizeUser for HmacCoreMode<D, SECRET> {
    type OutputSize = <<D as EagerHash>::Core as OutputSizeUser>::OutputSize;
}
impl<D: EagerHash, const SECRET: bool> KeyInit for HmacCoreMode<D, SECRET> {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts keys of any length")
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        #[cfg(not(feature = "secret-input"))]
        if SECRET { return Err(InvalidLength); }
        let mut state = Self::unkeyed();
        state.initialize_key_in_place(key);
        Ok(state)
    }
}
impl<D: EagerHash, const SECRET: bool> UpdateCore for HmacCoreMode<D, SECRET> {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) { self.digest.update_blocks(blocks); }
}
impl<D: EagerHash, const SECRET: bool> FixedOutputCore for HmacCoreMode<D, SECRET> {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut storage = Output::<D::Core>::default();
        let mut hash = ByteGuard::<_, SECRET>::new(&mut storage);
        self.digest.finalize_fixed_core(buffer, &mut hash);
        #[cfg(feature = "zeroize")]
        if SECRET {
            use digest::zeroize::Zeroize;
            buffer.zeroize();
        }
        buffer.reset();
        let h = &mut self.opad_digest;
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}
impl<D: EagerHash + AlgorithmName, const SECRET: bool> AlgorithmName for HmacCoreMode<D, SECRET> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}
impl<D: EagerHash> fmt::Debug for HmacCoreMode<D, false>
where D::Core: AlgorithmName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("HmacCore { ... }") }
}

/// Generic core HMAC instance, which operates over blocks.
pub struct HmacResetCore<D: EagerHash> {
    digest: D::Core,
    opad_digest: D::Core,
    ipad_digest: D::Core,
}

impl<D: EagerHash> Clone for HmacResetCore<D> {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            opad_digest: self.opad_digest.clone(),
            ipad_digest: self.ipad_digest.clone(),
        }
    }
}

impl<D: EagerHash> MacMarker for HmacResetCore<D> {}

impl<D: EagerHash> BufferKindUser for HmacResetCore<D> {
    type BufferKind = Eager;
}

impl<D: EagerHash> KeySizeUser for HmacResetCore<D> {
    type KeySize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> BlockSizeUser for HmacResetCore<D> {
    type BlockSize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> OutputSizeUser for HmacResetCore<D> {
    type OutputSize = <<D as EagerHash>::Core as OutputSizeUser>::OutputSize;
}

impl<D: EagerHash> KeyInit for HmacResetCore<D> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts keys of any length")
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut buf = get_der_key::<D>(key);
        buf.iter_mut().for_each(|b: &mut u8| *b ^= IPAD);

        let mut digest = D::Core::default();
        digest.update_blocks(slice::from_ref(&buf));

        buf.iter_mut().for_each(|b: &mut u8| *b ^= IPAD ^ OPAD);

        let mut opad_digest = D::Core::default();
        opad_digest.update_blocks(slice::from_ref(&buf));

        Ok(Self {
            ipad_digest: digest.clone(),
            opad_digest,
            digest,
        })
    }
}

impl<D: EagerHash> UpdateCore for HmacResetCore<D> {
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D: EagerHash> FixedOutputCore for HmacResetCore<D> {
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut hash = Output::<D::Core>::default();
        self.digest.finalize_fixed_core(buffer, &mut hash);
        // finalize_fixed_core should reset the buffer as well, but
        // to be extra safe we reset it explicitly again.
        buffer.reset();
        let mut h = self.opad_digest.clone();
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}

impl<D: EagerHash> Reset for HmacResetCore<D> {
    #[inline(always)]
    fn reset(&mut self) {
        self.digest = self.ipad_digest.clone();
    }
}

impl<D: EagerHash + AlgorithmName> AlgorithmName for HmacResetCore<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D: EagerHash> fmt::Debug for HmacResetCore<D>
where
    D::Core: AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacResetCore { ... }")
    }
}
