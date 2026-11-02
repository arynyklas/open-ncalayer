use digest::{
    Digest,
    block_api::{Block, BlockSizeUser},
};

pub(crate) const IPAD: u8 = 0x36;
pub(crate) const OPAD: u8 = 0x5C;

/// Borrowed scratch guard: the backing allocation remains owned by the caller.
/// Secret mode wipes even during unwinding; ordinary mode elides the cleanup.
pub(crate) struct ByteGuard<'a, T: AsMut<[u8]>, const SECRET: bool>(&'a mut T);

impl<'a, T: AsMut<[u8]>, const SECRET: bool> ByteGuard<'a, T, SECRET> {
    pub(crate) fn new(value: &'a mut T) -> Self { Self(value) }
}
impl<T: AsMut<[u8]>, const SECRET: bool> core::ops::Deref for ByteGuard<'_, T, SECRET> {
    type Target = T;
    fn deref(&self) -> &T { self.0 }
}
impl<T: AsMut<[u8]>, const SECRET: bool> core::ops::DerefMut for ByteGuard<'_, T, SECRET> {
    fn deref_mut(&mut self) -> &mut T { self.0 }
}
impl<T: AsMut<[u8]>, const SECRET: bool> Drop for ByteGuard<'_, T, SECRET> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        if SECRET {
            use digest::zeroize::Zeroize;
            self.0.as_mut().zeroize();
        }
    }
}

pub(crate) fn get_der_key<D: Digest + BlockSizeUser>(key: &[u8]) -> Block<D> {
    let mut der_key = Block::<D>::default();
    derive_key_into::<D, false>(key, &mut der_key);
    der_key
}

// Shared upstream normalization, including the long-key case. Secret users
// supply guarded output storage rather than receiving an unguarded key copy.
pub(crate) fn derive_key_into<D: Digest + BlockSizeUser, const SECRET: bool>(
    key: &[u8],
    der_key: &mut Block<D>,
) {
    if key.len() <= der_key.len() {
        der_key[..key.len()].copy_from_slice(key);
    } else {
        let mut storage = digest::Output::<D>::default();
        let mut hash = ByteGuard::<_, SECRET>::new(&mut storage);
        if SECRET {
            let mut state = D::new();
            Digest::update(&mut state, key);
            Digest::finalize_into(state, &mut hash);
        } else {
            *hash = D::digest(key);
        }
        if hash.len() <= der_key.len() {
            der_key[..hash.len()].copy_from_slice(&hash);
        } else {
            let n = der_key.len();
            der_key.copy_from_slice(&hash[..n]);
        }
    }
}

#[cfg(all(test, feature = "secret-input"))]
mod cleanup_tests {
    use super::ByteGuard;

    #[test]
    fn scratch_drop_wipes_live_storage() {
        let mut bytes = [0x5c; 64];
        { let _guard = ByteGuard::<_, true>::new(&mut bytes); }
        assert_eq!(bytes, [0; 64]);
    }

    #[test]
    fn scratch_unwind_wipes_live_storage() {
        extern crate std;
        let mut bytes = [0x36; 64];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ByteGuard::<_, true>::new(&mut bytes);
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert_eq!(bytes, [0; 64]);
    }
}

#[cfg(all(test, feature = "secret-input"))]
mod long_key_vectors {
    use crate::{HmacSecret, KeyInit, Mac};
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn rfc4231_long_key_normalization_and_multiblock_message() {
        // RFC4231 §§4.7/4.8. Tests the shared generic normalization branch,
        // not a claim of Streebog long-key oracle coverage or SHA2 cleanup.
        let cases: [(&[u8], [u8; 32]); 2] = [
            (b"Test Using Larger Than Block-Size Key - Hash Key First",
                hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")),
            (concat!("This is a test using a larger than block-size key and a larger ",
                "than block-size data. The key needs to be hashed before being used ",
                "by the HMAC algorithm.").as_bytes(),
                hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")),
        ];
        for (message, expected) in cases {
            for width in [1, 63, 64, 65] {
                let mut mac = <HmacSecret<Sha256> as KeyInit>::new_from_slice(&[0xaa; 131]).unwrap();
                for chunk in message.chunks(width) { Mac::update(&mut mac, chunk); }
                assert_eq!(&mac.finalize().into_bytes()[..], expected.as_slice());
            }
        }
    }
}
