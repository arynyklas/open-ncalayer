//! GOST hash functions used by the KZ PKI.

use gost94::{Digest, Gost94Test};
use streebog::{Streebog256, Streebog512};

/// GOST 34.311-95: GOST R 34.11-94 with the GOST 28147 "D-TEST" S-box (test parameter set).
///
/// This is the Java Kalkan provider used by NCALayer. An empty message hashes to the standard
/// `ce85b99c…`, not to the three-compression value attributed to native KalkanCrypt.
pub fn gost34311(data: &[u8]) -> [u8; 32] {
    Gost94Test::digest(data).into()
}

/// GOST 34.11-2015 (Streebog, GOST R 34.11-2012) with a 512-bit output.
pub fn streebog512(data: &[u8]) -> [u8; 64] {
    Streebog512::digest(data).into()
}

/// GOST 34.11-2015 (Streebog, GOST R 34.11-2012) with a 256-bit output.
pub fn streebog256(data: &[u8]) -> [u8; 32] {
    Streebog256::digest(data).into()
}
