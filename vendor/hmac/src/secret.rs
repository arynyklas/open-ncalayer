//! Stable buffered ownership, forwarding to the single shared HMAC core.

use crate::block_api::HmacCoreMode;
use alloc::boxed::Box;
use digest::{FixedOutput, InvalidLength, KeyInit, MacMarker, Output, Update};
use digest::block_api::{EagerHash, BlockSizeUser, Buffer, FixedOutputCore, OutputSizeUser, UpdateCore};
use digest::common::{Key, KeySizeUser};
use digest::zeroize::Zeroize;

struct BufferedSecret<D: EagerHash> {
    core: HmacCoreMode<D, true>,
    buffer: Buffer<HmacCoreMode<D, true>>,
}
impl<D: EagerHash> BufferedSecret<D> {
    fn unkeyed() -> Self {
        Self { core: HmacCoreMode::unkeyed(), buffer: Buffer::<HmacCoreMode<D, true>>::default() }
    }
    fn finish_and_clear(&mut self, out: &mut Output<HmacCoreMode<D, true>>) {
        self.core.finalize_fixed_core(&mut self.buffer, out);
        self.buffer.zeroize();
        // The selected digest core owns cleanup of its keyed state. G01 uses
        // SecretCore, whose state/workspace is stable and cleared in place.
    }
}

/// HMAC with stable buffered ownership and guarded normalization/inner output.
/// The concrete digest must itself provide stable zeroizing secret-input cores;
/// G01 instantiates this with Streebog256Secret, never an arbitrary fast digest.
/// No Clone, Debug, serialized state or raw-buffer decomposition is exposed.
#[expect(missing_debug_implementations, reason = "secret keyed state deliberately has no Debug surface")]
pub struct HmacSecret<D: EagerHash> { inner: Box<BufferedSecret<D>> }

impl<D: EagerHash> KeySizeUser for HmacSecret<D> {
    type KeySize = <HmacCoreMode<D, true> as KeySizeUser>::KeySize;
}
impl<D: EagerHash> BlockSizeUser for HmacSecret<D> {
    type BlockSize = <HmacCoreMode<D, true> as BlockSizeUser>::BlockSize;
}
impl<D: EagerHash> OutputSizeUser for HmacSecret<D> {
    type OutputSize = <HmacCoreMode<D, true> as OutputSizeUser>::OutputSize;
}
impl<D: EagerHash> KeyInit for HmacSecret<D> {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts any key length")
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        // All allocations/unkeyed moves occur before applying secret key bytes.
        let mut state = Self { inner: Box::new(BufferedSecret::unkeyed()) };
        state.inner.core.initialize_key_in_place(key);
        Ok(state)
    }
}
impl<D: EagerHash> MacMarker for HmacSecret<D> {}
impl<D: EagerHash> Update for HmacSecret<D> {
    fn update(&mut self, input: &[u8]) {
        let BufferedSecret { core, buffer } = &mut *self.inner;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}
impl<D: EagerHash> FixedOutput for HmacSecret<D> {
    fn finalize_into(mut self, out: &mut Output<Self>) {
        // The consuming trait moves a Box handle, not cores or partial key data.
        self.inner.finish_and_clear(out);
    }
}
