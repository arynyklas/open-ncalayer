//! The public keys an index must be signed with, built in from `keys/current.pub` and
//! `keys/next.pub` (the next key, for rotation) when the build has them.

use minisign_verify::PublicKey;

use crate::UpdateError;

/// The text of each key file present at build time.
const EMBEDDED: &[&str] = include!(concat!(env!("OUT_DIR"), "/keys.rs"));

/// The keys built into this program; empty if the build had none, and then nothing can be
/// verified: the updater is off.
///
/// # Errors
///
/// [`UpdateError::BadKey`] if a built-in key file is not a minisign public key.
pub fn embedded_keys() -> Result<Vec<PublicKey>, UpdateError> {
    decode(EMBEDDED)
}

fn decode(files: &[&str]) -> Result<Vec<PublicKey>, UpdateError> {
    files
        .iter()
        .map(|text| PublicKey::decode(text).map_err(|e| UpdateError::BadKey(e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_keys_are_readable() {
        // Whatever this build carries (nothing in a checkout without keys) decodes.
        assert_eq!(embedded_keys().unwrap().len(), EMBEDDED.len());
    }

    #[test]
    fn key_files_are_decoded_or_refused() {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let text = pair.pk.to_box().unwrap().into_string();
        assert_eq!(decode(&[&text, &text]).unwrap().len(), 2);
        assert_eq!(decode(&[]).unwrap().len(), 0);
        assert!(matches!(
            decode(&[&text, "untrusted comment: x\nnot a key\n"]),
            Err(UpdateError::BadKey(_))
        ));
    }
}
