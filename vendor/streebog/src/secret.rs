//! Stable secret-input adapters over the single shared Streebog compression core.

use crate::block_api::{CompressionWorkspace, StreebogCore};
use alloc::boxed::Box;
use core::{fmt, marker::PhantomData};
use digest::{FixedOutput, HashMarker, Output, Update};
use digest::array::ArraySize;
use digest::block_api::{AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser,
    Eager, EagerHash, FixedOutputCore, OutputSizeUser, UpdateCore, VariableOutputCore};
use digest::consts::{U32, U64};
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

struct FullOutputGuard<'a>(&'a mut Output<StreebogCore<true>>);
impl core::ops::Deref for FullOutputGuard<'_> {
    type Target = Output<StreebogCore<true>>;
    fn deref(&self) -> &Self::Target { self.0 }
}
impl core::ops::DerefMut for FullOutputGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.0 }
}
impl Drop for FullOutputGuard<'_> {
    fn drop(&mut self) { self.0.as_mut_slice().zeroize(); }
}

// Every by-value construction of this allocation precedes secret input.
// Once keyed, only Box handles move; workspace is reused, never allocated per block.
struct CoreAllocation {
    core: StreebogCore<true>,
    work: CompressionWorkspace<true>,
    full: Output<StreebogCore<true>>,
}
impl Drop for CoreAllocation {
    fn drop(&mut self) { self.full.as_mut_slice().zeroize(); }
}

/// Stable core owner required by the existing EagerHash trait.
/// Clone allocates a public-initialized destination, then fills it in place.
pub struct SecretCore<N: ArraySize> {
    inner: Box<CoreAllocation>,
    output: PhantomData<N>,
}
impl<N: ArraySize> SecretCore<N> {
    fn copy_state_into(&self, destination: &mut Self) {
        self.inner.core.copy_state_into(&mut destination.inner.core);
    }
}
impl<N: ArraySize> Clone for SecretCore<N> {
    fn clone(&self) -> Self {
        let mut destination = Self::default();
        self.copy_state_into(&mut destination);
        destination
    }
}
impl<N: ArraySize> Default for SecretCore<N> {
    fn default() -> Self {
        Self {
            inner: Box::new(CoreAllocation {
                core: StreebogCore::new(N::USIZE).expect("Streebog output must be 32 or 64 bytes"),
                work: CompressionWorkspace::default(),
                full: Output::<StreebogCore<true>>::default(),
            }),
            output: PhantomData,
        }
    }
}
impl<N: ArraySize> HashMarker for SecretCore<N> {}
impl<N: ArraySize> BlockSizeUser for SecretCore<N> { type BlockSize = U64; }
impl<N: ArraySize> BufferKindUser for SecretCore<N> { type BufferKind = Eager; }
impl<N: ArraySize> OutputSizeUser for SecretCore<N> { type OutputSize = N; }
impl<N: ArraySize> UpdateCore for SecretCore<N> {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        let CoreAllocation { core, work, .. } = &mut *self.inner;
        core.update_with_workspace(blocks, work);
    }
}
impl<N: ArraySize> FixedOutputCore for SecretCore<N> {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let CoreAllocation { core, work, full } = &mut *self.inner;
        let mut full = FullOutputGuard(full);
        core.finish_with_workspace(buffer, &mut full, work);
        out.copy_from_slice(&full[64 - N::USIZE..]);
    }
}
impl<N: ArraySize> AlgorithmName for SecretCore<N> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreebogSecret_{}", N::USIZE)
    }
}
impl<N: ArraySize> ZeroizeOnDrop for SecretCore<N> {}

struct BufferedSecret<N: ArraySize> {
    core: SecretCore<N>,
    buffer: Buffer<SecretCore<N>>,
}
impl<N: ArraySize> Default for BufferedSecret<N> {
    fn default() -> Self { Self { core: SecretCore::default(), buffer: Buffer::<SecretCore<N>>::default() } }
}
impl<N: ArraySize> BufferedSecret<N> {
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
    fn finish_and_clear(&mut self, out: &mut Output<SecretCore<N>>) {
        self.core.finalize_fixed_core(&mut self.buffer, out);
    }
    fn copy_state_into(&self, destination: &mut Self) {
        self.core.copy_state_into(&mut destination.core);
        // Eager partial input is <64 bytes; this copies directly into the
        // already allocated destination buffer, never returns a secret buffer.
        destination.update(self.buffer.get_data());
    }
}

// Buffered wrapper duplication is trait forwarding only, not duplicated crypto.
macro_rules! secret_hash {
    ($name:ident, $size:ty) => {
        /// Explicit secret-input hash with stable core and partial-buffer owners.
        /// Clone is required by EagerHash; each clone retains zeroizing ownership.
        /// No Debug, serialized state or raw-buffer decomposition is exposed.
        pub struct $name { inner: Box<BufferedSecret<$size>> }
        impl Default for $name {
            fn default() -> Self { Self { inner: Box::new(BufferedSecret::default()) } }
        }
        impl Clone for $name {
            fn clone(&self) -> Self {
                let mut destination = Self::default();
                self.inner.copy_state_into(&mut destination.inner);
                destination
            }
        }
        impl HashMarker for $name {}
        impl BlockSizeUser for $name { type BlockSize = U64; }
        impl OutputSizeUser for $name { type OutputSize = $size; }
        impl Update for $name {
            fn update(&mut self, input: &[u8]) { self.inner.update(input); }
        }
        impl FixedOutput for $name {
            fn finalize_into(mut self, out: &mut Output<Self>) {
                self.inner.finish_and_clear(out);
            }
        }
        impl EagerHash for $name { type Core = SecretCore<$size>; }
        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                SecretCore::<$size>::write_alg_name(f)
            }
        }
        impl ZeroizeOnDrop for $name {}
    };
}
secret_hash!(Streebog256Secret, U32);
secret_hash!(Streebog512Secret, U64);

#[cfg(test)]
mod output_cleanup_tests {
    use super::*;

    #[test]
    fn output_guard_drop_clears_live_hybrid_array() {
        let mut storage = Output::<StreebogCore<true>>::default();
        storage.fill(0xa5);
        { let _guard = FullOutputGuard(&mut storage); }
        assert!(storage.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn output_guard_unwind_clears_live_hybrid_array() {
        extern crate std;
        let mut storage = Output::<StreebogCore<true>>::default();
        storage.fill(0x5a);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = FullOutputGuard(&mut storage);
            panic!("synthetic output unwind");
        }));
        assert!(result.is_err());
        assert!(storage.iter().all(|&byte| byte == 0));
    }
}
