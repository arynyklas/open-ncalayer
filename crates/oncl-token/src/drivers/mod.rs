//! A driver per token family: the APDUs that open the token, verify the PIN, list the keys
//! with their public keys and certificates, and sign. Only reading and signing: nothing is
//! ever written to a token.

pub mod kaztoken;
pub mod kzid;
pub mod util;

pub use kzid::read_id_card;

use crate::card::Card;
use crate::error::TokenError;
use crate::kind::TokenKind;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};

/// A key on a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    /// Alias, as the token names the key.
    pub alias: String,
    /// The token's reference of the key (file, object or key reference).
    pub id: u16,
    /// Key type.
    pub alg: KeyAlg,
}

/// Holder data of an ID card, read without the PIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdCardInfo {
    /// Individual identification number (12 digits).
    pub iin: String,
    /// Last name.
    pub last_name: String,
    /// First name.
    pub first_name: String,
    /// Middle name, when the holder has one.
    pub middle_name: Option<String>,
}

impl IdCardInfo {
    /// `"Last First Middle"`, or `"Last First"` without a middle name.
    pub fn full_name(&self) -> String {
        match &self.middle_name {
            Some(middle) => format!("{} {} {middle}", self.last_name, self.first_name),
            None => format!("{} {}", self.last_name, self.first_name),
        }
    }
}

/// A token family's commands, on an opened token.
pub trait Driver: Send {
    /// Family.
    fn kind(&self) -> TokenKind;

    /// Identifier of this very token (from its serial number).
    fn token_id(&self) -> &str;

    /// Checks that `pin` fits the token, before any command.
    ///
    /// # Errors
    ///
    /// [`TokenError::InvalidPin`].
    fn check_pin(&self, pin: &str) -> Result<(), TokenError> {
        check_pin(self.kind(), pin)
    }

    /// Verifies the PIN.
    ///
    /// # Errors
    ///
    /// [`TokenError::WrongPin`], [`TokenError::PinBlocked`], [`TokenError::InvalidPin`],
    /// transport and card errors.
    fn verify_pin(&mut self, card: &mut Card<'_>, pin: &str) -> Result<(), TokenError>;

    /// The keys on the token, in its order.
    ///
    /// # Errors
    ///
    /// Transport and card errors.
    fn keys(&mut self, card: &mut Card<'_>) -> Result<Vec<KeySlot>, TokenError>;

    /// Public key of a key.
    ///
    /// # Errors
    ///
    /// Transport and card errors, [`TokenError::Malformed`] for a key the card encodes
    /// wrongly.
    fn public_key(&mut self, card: &mut Card<'_>, slot: &KeySlot) -> Result<PublicKey, TokenError>;

    /// Certificate (DER) of a key; `None` when the token has none for it.
    ///
    /// # Errors
    ///
    /// Transport and card errors, [`TokenError::Malformed`] for a broken compressed
    /// certificate.
    fn certificate(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
    ) -> Result<Option<Vec<u8>>, TokenError>;

    /// Signs with the key, the PIN verified. `digest` is the hash for GOST and the DER
    /// `DigestInfo` for RSA. The result is in the format of software keys: GOST
    /// `r_LE ‖ s_LE`, RSA big-endian.
    ///
    /// # Errors
    ///
    /// Transport and card errors.
    fn sign(
        &mut self,
        card: &mut Card<'_>,
        slot: &KeySlot,
        alg: SigAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, TokenError>;

    /// Ends the PIN verification.
    ///
    /// # Errors
    ///
    /// Transport and card errors.
    fn logout(&mut self, card: &mut Card<'_>) -> Result<(), TokenError>;
}

/// Checks that `pin` fits a token of `kind`: ASCII, not empty, and the family's length
/// (4 for the ID card, 6..=32 for AKey, at most 255 bytes otherwise).
///
/// # Errors
///
/// [`TokenError::InvalidPin`].
pub fn check_pin(kind: TokenKind, pin: &str) -> Result<(), TokenError> {
    let fits = match kind {
        TokenKind::KzIdCard => pin.len() == 4,
        TokenKind::AKey => (6..=32).contains(&pin.len()),
        TokenKind::Kaztoken | TokenKind::EToken72K | TokenKind::EToken5110 | TokenKind::JaCarta => {
            (1..=255).contains(&pin.len())
        }
    };
    if pin.is_ascii() && fits {
        Ok(())
    } else {
        Err(TokenError::InvalidPin)
    }
}

/// Opens the token of `kind` in `card`: selects its applet or reads its serial number.
///
/// # Errors
///
/// [`TokenError::WrongCard`] when the card does not answer as a token of `kind`; transport
/// errors.
pub fn open_driver(kind: TokenKind, card: &mut Card<'_>) -> Result<Box<dyn Driver>, TokenError> {
    match kind {
        TokenKind::Kaztoken => Ok(Box::new(kaztoken::Kaztoken::open(card)?)),
        TokenKind::KzIdCard => Ok(Box::new(kzid::KzIdCard::open(card)?)),
        TokenKind::EToken72K | TokenKind::EToken5110 | TokenKind::JaCarta | TokenKind::AKey => Err(
            TokenError::Malformed(format!("no driver for {} yet", kind.storage_name())),
        ),
    }
}

/// A card status refusing the opening command: the card is not this token.
fn wrong_card(e: TokenError) -> TokenError {
    match e {
        TokenError::Card { .. } => TokenError::WrongCard,
        e => e,
    }
}
