use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block as GenBlock, BlockSizeUser, Buffer, BufferKindUser, Eager,
        OutputSizeUser, TruncSide, UpdateCore, VariableOutputCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U64, U192},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{BLOCK_SIZE, C64, SHUFFLED_LIN_TABLE};

type Block = [u8; 64];

/// Ordinary upstream core; the alias preserves non-generic call inference.
pub type StreebogVarCore = StreebogCore<false>;

/// Shared Streebog core. Secret mode is available with `secret-input` only.
/// Both modes reuse the same compression, constants and finalization.
pub struct StreebogCore<const SECRET: bool> {
    h: [u64; 8],
    n: [u64; 8],
    sigma: [u64; 8],
}

impl Clone for StreebogCore<false> {
    fn clone(&self) -> Self { Self { h: self.h, n: self.n, sigma: self.sigma } }
}

/// One reusable operation workspace; secret owners allocate this before input.
pub(crate) struct CompressionWorkspace<const SECRET: bool> {
    message: [u64; 8],
    key: [u64; 8],
    block: [u64; 8],
    lps: [u64; 8],
    // Selected input byte and candidate contribution belong to the same
    // cleared owner, not a readonly eight-word snapshot in the caller frame.
    selector: [u64; 2],
}
impl<const SECRET: bool> Default for CompressionWorkspace<SECRET> {
    fn default() -> Self {
        Self { message: [0; 8], key: [0; 8], block: [0; 8], lps: [0; 8], selector: [0; 2] }
    }
}
impl<const SECRET: bool> CompressionWorkspace<SECRET> {
    fn clear(&mut self) {
        #[cfg(feature = "zeroize")]
        if SECRET {
            self.message.zeroize();
            self.key.zeroize();
            self.block.zeroize();
            self.lps.zeroize();
            self.selector.zeroize();
        }
    }
}
impl<const SECRET: bool> Drop for CompressionWorkspace<SECRET> {
    fn drop(&mut self) { self.clear(); }
}

struct WordsGuard<'a, const SECRET: bool, const LEN: usize = 8>(&'a mut [u64; LEN]);

impl<const SECRET: bool, const LEN: usize> core::ops::Deref for WordsGuard<'_, SECRET, LEN> {
    type Target = [u64; LEN];
    fn deref(&self) -> &Self::Target { self.0 }
}

impl<const SECRET: bool, const LEN: usize> core::ops::DerefMut for WordsGuard<'_, SECRET, LEN> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.0 }
}

impl<const SECRET: bool, const LEN: usize> Drop for WordsGuard<'_, SECRET, LEN> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        if SECRET { self.0.zeroize(); }
    }
}

#[inline(always)]
fn lps<const SECRET: bool>(
    h: &mut [u64; 8], n: &[u64; 8], scratch: &mut [u64; 8], _selector: &mut [u64; 2],
) {
    for i in 0..8 { h[i] ^= n[i]; }
    let mut buf = WordsGuard::<SECRET>(scratch);
    buf.fill(0);
    #[cfg(feature = "secret-input")]
    let mut selected = WordsGuard::<SECRET, 2>(_selector);
    for i in 0..8 {
        for j in 0..8 {
            #[cfg(feature = "secret-input")]
            if SECRET {
                use subtle::{ConditionallySelectable, ConstantTimeEq};
                // The inspected pinned x64 code cached all eight transformed
                // key words across this scan, then left those stack slots
                // unwiped. Reload one public row through a MUTABLE source;
                // per-candidate barriers keep selector/accumulator in their
                // cleared workspace rather than an immutable word snapshot.
                // This is a codegen candidate, not a spill-erasure guarantee.
                let source = core::hint::black_box(&mut *h);
                selected[0] = (source[j] >> (8 * i)) & 0xff;
                for (candidate, value) in SHUFFLED_LIN_TABLE[j].iter().enumerate() {
                    let selected = core::hint::black_box(&mut *selected);
                    let choice = (candidate as u8).ct_eq(&(selected[0] as u8));
                    selected[1] = u64::conditional_select(&0, value, choice);
                    let accumulator = core::hint::black_box(&mut *buf);
                    accumulator[i] ^= selected[1];
                }
                continue;
            }
            let idx = ((h[j] >> (8 * i)) & 0xff) as usize;
            buf[i] ^= SHUFFLED_LIN_TABLE[j][idx];
        }
    }
    h.copy_from_slice(&*buf);
}

#[inline(always)]
fn g<const SECRET: bool>(h: &mut [u64; 8], n: &[u64; 8], work: &mut CompressionWorkspace<SECRET>) {
    work.key.copy_from_slice(h);
    work.block.copy_from_slice(&work.message);
    lps::<SECRET>(&mut work.key, n, &mut work.lps, &mut work.selector);
    for c in &C64 {
        lps::<SECRET>(&mut work.block, &work.key, &mut work.lps, &mut work.selector);
        lps::<SECRET>(&mut work.key, c, &mut work.lps, &mut work.selector);
    }
    // Keep feed-forward input in its owned workspace rather than a separately
    // hoisted eight-word copy across the secret compression calls. This is an
    // optimizer barrier on the pointer, NOT proof of absence of scalar spills.
    let work = if SECRET { core::hint::black_box(work) } else { work };
    let h = if SECRET { core::hint::black_box(h) } else { h };
    for i in 0..8 { h[i] ^= work.block[i] ^ work.key[i] ^ work.message[i]; }
}

impl<const SECRET: bool> StreebogCore<SECRET> {
    #[inline(always)]
    fn update_sigma(&mut self, m: &[u64; 8]) {
        let mut carry = false;
        for i in 0..8 { adc(&mut self.sigma[i], m[i], &mut carry); }
    }
    #[inline(always)]
    fn update_n(&mut self, len: u64) {
        let mut carry = false;
        adc(&mut self.n[0], 8 * len, &mut carry);
        for i in 1..8 { adc(&mut self.n[i], 0, &mut carry); }
    }
    #[inline(always)]
    fn compress_message(&mut self, msg_len: u64, work: &mut CompressionWorkspace<SECRET>) {
        g::<SECRET>(&mut self.h, &self.n, work);
        self.update_n(msg_len);
        self.update_sigma(&work.message);
        work.clear();
    }
    #[inline(always)]
    pub(crate) fn update_with_workspace(
        &mut self, blocks: &[GenBlock<Self>], work: &mut CompressionWorkspace<SECRET>,
    ) {
        for block in blocks {
            for (word, bytes) in work.message.iter_mut().zip(block.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            self.compress_message(BLOCK_SIZE as u64, work);
        }
    }
    #[inline(always)]
    pub(crate) fn finish_with_workspace(
        &mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>,
        work: &mut CompressionWorkspace<SECRET>,
    ) {
        let pos = buffer.get_pos();
        work.message.fill(0);
        for (i, byte) in buffer.get_data().iter().enumerate() {
            work.message[i / 8] |= u64::from(*byte) << (8 * (i % 8));
        }
        work.message[pos / 8] |= 1u64 << (8 * (pos % 8));
        #[cfg(feature = "zeroize")]
        if SECRET { buffer.zeroize(); }
        buffer.reset();
        self.compress_message(pos as u64, work);
        work.message.copy_from_slice(&self.n);
        g::<SECRET>(&mut self.h, &[0; 8], work);
        work.clear();
        work.message.copy_from_slice(&self.sigma);
        g::<SECRET>(&mut self.h, &[0; 8], work);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (self.h[i / 8] >> (8 * (i % 8))) as u8;
        }
        work.clear();
        #[cfg(feature = "zeroize")]
        if SECRET {
            self.h.zeroize();
            self.n.zeroize();
            self.sigma.zeroize();
        }
    }
}

#[cfg(feature = "secret-input")]
impl StreebogCore<true> {
    pub(crate) fn copy_state_into(&self, target: &mut Self) {
        target.h.copy_from_slice(&self.h);
        target.n.copy_from_slice(&self.n);
        target.sigma.copy_from_slice(&self.sigma);
    }
}

impl<const SECRET: bool> HashMarker for StreebogCore<SECRET> {}
impl<const SECRET: bool> BlockSizeUser for StreebogCore<SECRET> { type BlockSize = U64; }
impl<const SECRET: bool> BufferKindUser for StreebogCore<SECRET> { type BufferKind = Eager; }
impl<const SECRET: bool> OutputSizeUser for StreebogCore<SECRET> { type OutputSize = U64; }

impl<const SECRET: bool> UpdateCore for StreebogCore<SECRET> {
    fn update_blocks(&mut self, blocks: &[GenBlock<Self>]) {
        #[cfg(feature = "secret-input")]
        if SECRET {
            // Raw block-level callers lack a retained workspace; one allocation
            // per call, not per block. Public secret wrappers reuse their owner.
            let mut work = alloc::boxed::Box::new(CompressionWorkspace::default());
            self.update_with_workspace(blocks, &mut work);
            return;
        }
        let mut work = CompressionWorkspace::default();
        self.update_with_workspace(blocks, &mut work);
    }
}

impl<const SECRET: bool> VariableOutputCore for StreebogCore<SECRET> {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        #[cfg(not(feature = "secret-input"))]
        if SECRET { return Err(InvalidOutputSize); }
        let h = match output_size {
            32 => [0x0101_0101_0101_0101; 8],
            64 => [0; 8],
            _ => return Err(InvalidOutputSize),
        };
        Ok(Self { h, n: [0; 8], sigma: [0; 8] })
    }
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        #[cfg(feature = "secret-input")]
        if SECRET {
            let mut work = alloc::boxed::Box::new(CompressionWorkspace::default());
            self.finish_with_workspace(buffer, out, &mut work);
            return;
        }
        let mut work = CompressionWorkspace::default();
        self.finish_with_workspace(buffer, out, &mut work);
    }
}

impl<const SECRET: bool> AlgorithmName for StreebogCore<SECRET> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Streebog") }
}

impl fmt::Debug for StreebogCore<false> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreebogVarCore { ... }")
    }
}

impl<const SECRET: bool> Drop for StreebogCore<SECRET> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.h.zeroize();
            self.n.zeroize();
            self.sigma.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const SECRET: bool> ZeroizeOnDrop for StreebogCore<SECRET> {}

// The existing public mode keeps its upstream serialization API.
// Secret cores/wrappers deliberately do not implement SerializableState.
impl SerializableState for StreebogCore<false> {
    type SerializedStateSize = U192;
    fn serialize(&self) -> SerializedState<Self> {
        let ser_h: Array<u8, U64> = to_bytes(&self.h).into();
        let ser_n: Array<u8, U64> = to_bytes(&self.n).into();
        let ser_sigma: Array<u8, U64> = to_bytes(&self.sigma).into();
        ser_h.concat(ser_n).concat(ser_sigma)
    }
    fn deserialize(ser_state: &SerializedState<Self>) -> Result<Self, DeserializeStateError> {
        let (ser_h, rem) = ser_state.split::<U64>();
        let (ser_n, ser_sigma) = rem.split::<U64>();
        Ok(Self {
            h: from_bytes(&ser_h.into()),
            n: from_bytes(&ser_n.into()),
            sigma: from_bytes(&ser_sigma.into()),
        })
    }
}

// This function mirrors implementation of the `carrying_add` method:
// https://github.com/rust-lang/rust/blob/9cdfe28/library/core/src/num/uint_macros.rs#L2060-L2066
#[inline(always)]
fn adc(v1: &mut u64, v2: u64, carry: &mut bool) {
    let (a, b) = v1.overflowing_add(v2);
    let (c, d) = a.overflowing_add(*carry as u64);
    *v1 = c;
    *carry = b | d;
}

#[inline(always)]
fn to_bytes(b: &[u64; 8]) -> Block {
    let mut t = [0; 64];
    for (chunk, v) in t.chunks_exact_mut(8).zip(b.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    t
}

#[inline(always)]
fn from_bytes(b: &Block) -> [u64; 8] {
    let mut t = [0u64; 8];
    for (v, chunk) in t.iter_mut().zip(b.chunks_exact(8)) {
        *v = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_carry_propagates_to_top_limb() {
        let mut core = StreebogVarCore {
            h: [0u64; 8],
            n: [0u64; 8],
            sigma: [0u64; 8],
        };
        core.n[0] = u64::MAX - 511;
        for i in 1..=6 {
            core.n[i] = u64::MAX;
        }
        core.n[7] = 0;
        core.update_n(64);
        for i in 0..=6 {
            assert_eq!(core.n[i], 0);
        }
        assert_eq!(core.n[7], 1);
    }

    #[test]
    fn counter_zero_len_no_change() {
        let mut core = StreebogVarCore {
            h: [0u64; 8],
            n: [1, 2, 3, 4, 5, 6, 7, 8],
            sigma: [0u64; 8],
        };
        let before = core.n;
        core.update_n(0);
        assert_eq!(core.n, before);
    }
}

#[cfg(all(test, feature = "secret-input"))]
mod secret_cleanup_tests {
    use super::WordsGuard;

    #[test]
    fn scratch_drop_clears_live_backing_storage() {
        let mut words = [u64::MAX; 8];
        { let _guard = WordsGuard::<true>(&mut words); }
        assert_eq!(words, [0; 8]);
    }

    #[test]
    fn scratch_unwind_clears_live_backing_storage() {
        extern crate std;
        let mut words = [u64::MAX; 8];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = WordsGuard::<true>(&mut words);
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert_eq!(words, [0; 8]);
    }

    #[test]
    fn secret_finalize_clears_actual_live_core_before_return() {
        use super::{Buffer, Output, StreebogCore, VariableOutputCore};
        use hex_literal::hex;
        // RFC6986 M1/256, full bit-vector literals reversed once into bytes.
        let mut message = hex!(
            "32313039383736353433323130393837"
            "36353433323130393837363534333231"
            "30393837363534333231303938373635"
            "343332313039383736353433323130");
        message.reverse();
        let mut expected = hex!("00557be5e584fd52a449b16b0251d05d"
            "27f94ab76cbaa6da890b59d8ef1e159d");
        expected.reverse();
        let mut core = StreebogCore::<true>::new(32).unwrap();
        let mut buffer = Buffer::<StreebogCore<true>>::try_new(&message).unwrap();
        let mut output = Output::<StreebogCore<true>>::default();
        core.finalize_variable_core(&mut buffer, &mut output);
        assert_eq!(&output[32..], expected.as_slice());
        assert_eq!(core.h, [0; 8], "live finalizer source h was not cleared");
        assert_eq!(core.n, [0; 8], "live finalizer source counter was not cleared");
        assert_eq!(core.sigma, [0; 8], "live finalizer source sigma was not cleared");
        assert!(buffer.get_data().is_empty());
        // These are the real still-live owned fields, not a standalone dummy
        // guard and not proof of absence of additional emitted stack spills.
    }

    #[test]
    fn selector_owner_clear_covers_new_secret_fields() {
        let mut work = super::CompressionWorkspace::<true>::default();
        work.selector = [0xab, 0xfedc_ba98_7654_3210];
        work.clear();
        assert_eq!(work.selector, [0; 2]);
    }

    #[test]
    fn selector_guard_unwind_clears_live_workspace() {
        extern crate std;
        let mut work = super::CompressionWorkspace::<true>::default();
        work.selector = [0xab, 0xfedc_ba98_7654_3210];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = WordsGuard::<true, 2>(&mut work.selector);
            panic!("synthetic selector unwind");
        }));
        assert!(result.is_err());
        assert_eq!(work.selector, [0; 2]);
    }
}
