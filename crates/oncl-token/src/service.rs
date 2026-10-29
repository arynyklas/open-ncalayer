//! The token service: which tokens are plugged in, opening one with its PIN into key
//! entries, and keys that sign on the card.
//!
//! Every operation runs in one transaction of its own: connect, begin, the commands, end,
//! disconnect with a reset of the card (which ends the PIN verification for every process).
//! A key keeps the PIN in memory for its signatures; once the token refused it, the key
//! never sends it again.

use crate::backend::{Backend, Connection, NullBackend};
use crate::card::{Card, trace_enabled};
use crate::drivers::{Driver, KeySlot, check_pin, open_driver};
use crate::error::TokenError;
use crate::kind::TokenKind;
use der::Decode;
use oncl_pki::key::{KeyAlg, KeyError, PublicKey, SigAlg, TokenKey, TokenSigner, digest_info};
use oncl_pki::pkcs12::KeyEntry;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use x509_cert::Certificate;
use zeroize::Zeroizing;

/// A token found by a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Present {
    /// Family.
    pub kind: TokenKind,
    /// Reader it is in.
    pub reader: String,
}

/// Why a scan saw nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanProblem {
    /// The smart card service is not available.
    NoService,
    /// The service failed.
    Failed(String),
}

/// The tokens plugged in, in the order of the readers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Tokens of a known family.
    pub present: Vec<Present>,
    /// A problem of the service; having no reader is not one.
    pub problem: Option<ScanProblem>,
}

/// The process's tokens: one service behind it, support on or off.
pub struct Tokens {
    backend: Arc<dyn Backend>,
    enabled: AtomicBool,
    trace: AtomicBool,
}

impl Tokens {
    /// Tokens through `backend`; with support off nothing reaches the backend. The APDU
    /// trace is on when [`crate::TRACE_VAR`] is `1`.
    pub fn new(backend: Arc<dyn Backend>, enabled: bool) -> Arc<Tokens> {
        Arc::new(Tokens {
            backend,
            enabled: AtomicBool::new(enabled),
            trace: AtomicBool::new(trace_enabled()),
        })
    }

    /// No tokens: support off, no service.
    pub fn disabled() -> Arc<Tokens> {
        Tokens::new(Arc::new(NullBackend), false)
    }

    /// Turns token support on or off.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    /// Token support is on.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Turns the APDU trace of later operations on or off.
    pub fn set_trace(&self, on: bool) {
        self.trace.store(on, Ordering::SeqCst);
    }

    fn trace(&self) -> bool {
        self.trace.load(Ordering::SeqCst)
    }

    /// The tokens plugged in; nothing with support off.
    pub fn scan(&self) -> Scan {
        if !self.is_enabled() {
            return Scan::default();
        }
        match self.backend.readers() {
            Ok(readers) => Scan {
                present: readers
                    .into_iter()
                    .filter_map(|r| {
                        let kind = TokenKind::from_atr(r.atr.as_deref()?)?;
                        Some(Present {
                            kind,
                            reader: r.name,
                        })
                    })
                    .collect(),
                problem: None,
            },
            Err(crate::backend::BackendError::NoReaders) => Scan::default(),
            Err(crate::backend::BackendError::NoService) => Scan {
                present: Vec::new(),
                problem: Some(ScanProblem::NoService),
            },
            Err(e) => Scan {
                present: Vec::new(),
                problem: Some(ScanProblem::Failed(e.to_string())),
            },
        }
    }

    /// The readers holding a token of `kind`; none with support off, without the service
    /// or without readers.
    ///
    /// # Errors
    ///
    /// [`TokenError::Transport`] when the service fails otherwise.
    pub fn readers(&self, kind: TokenKind) -> Result<Vec<String>, TokenError> {
        let scan = self.scan();
        if let Some(ScanProblem::Failed(e)) = scan.problem {
            return Err(TokenError::Transport(e));
        }
        Ok(scan
            .present
            .into_iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.reader)
            .collect())
    }

    /// A card of any kind is in some reader.
    pub fn any_card(&self) -> bool {
        self.is_enabled()
            && self
                .backend
                .readers()
                .is_ok_and(|readers| readers.iter().any(|r| r.atr.is_some()))
    }

    /// Opens the token of `kind` in `reader` with `pin`: its keys that have a certificate
    /// matching their public key, in the token's order, as entries whose keys sign on the
    /// card.
    ///
    /// # Errors
    ///
    /// [`TokenError::Disabled`] with support off; [`TokenError::InvalidPin`] before any
    /// command; [`TokenError::NoDevice`] when the reader holds no token of `kind`; the PIN,
    /// card and transport errors.
    pub fn open(
        &self,
        reader: &str,
        kind: TokenKind,
        pin: &str,
    ) -> Result<Vec<KeyEntry>, TokenError> {
        if !self.is_enabled() {
            return Err(TokenError::Disabled);
        }
        check_pin(kind, pin)?;
        let trace = self.trace();
        let mut conn = connect(&*self.backend, reader, kind)?;
        let (token_id, keys) = in_transaction(&mut *conn, |conn| {
            let mut card = Card::new(conn, trace);
            let mut driver = open_driver(kind, &mut card)?;
            driver.verify_pin(&mut card, pin)?;
            let mut keys = Vec::new();
            for slot in driver.keys(&mut card)? {
                if let Some(pair) = pair(&mut *driver, &mut card, slot)? {
                    keys.push(pair);
                }
            }
            logout(&mut *driver, &mut card);
            Ok((driver.token_id().to_owned(), keys))
        })?;
        Ok(keys
            .into_iter()
            .map(|(slot, public, cert)| {
                let key = CardKey {
                    backend: self.backend.clone(),
                    reader: reader.to_owned(),
                    kind,
                    token_id: token_id.clone(),
                    slot,
                    public,
                    pin: Zeroizing::new(pin.to_owned()),
                    pin_rejected: AtomicBool::new(false),
                    trace,
                };
                KeyEntry {
                    alias: key.slot.alias.clone(),
                    key: oncl_pki::key::PrivateKey::Token(TokenKey::new(Arc::new(key))),
                    cert,
                }
            })
            .collect())
    }
}

/// Connects to `reader`, whose card must have an ATR of `kind`.
fn connect(
    backend: &dyn Backend,
    reader: &str,
    kind: TokenKind,
) -> Result<Box<dyn Connection>, TokenError> {
    let conn = backend.connect(reader)?;
    if TokenKind::from_atr(conn.atr()) != Some(kind) {
        return Err(TokenError::NoDevice);
    }
    Ok(conn)
}

/// Runs `f` in a transaction, which ends whatever `f` returns.
fn in_transaction<T>(
    conn: &mut dyn Connection,
    f: impl FnOnce(&mut dyn Connection) -> Result<T, TokenError>,
) -> Result<T, TokenError> {
    conn.begin_transaction()?;
    let out = f(conn);
    if let Err(e) = conn.end_transaction() {
        tracing::debug!("ending the smart card transaction: {e}");
    }
    out
}

/// Logs out; a failure only matters to the log, the disconnect resets the card anyway.
fn logout(driver: &mut dyn Driver, card: &mut Card<'_>) {
    if let Err(e) = driver.logout(card) {
        tracing::debug!("{}: logging out: {e}", driver.kind().storage_name());
    }
}

/// A key with its certificate, when the token has one that matches the key's public key.
fn pair(
    driver: &mut dyn Driver,
    card: &mut Card<'_>,
    slot: KeySlot,
) -> Result<Option<(KeySlot, PublicKey, Certificate)>, TokenError> {
    let family = driver.kind().storage_name();
    let skipped = |alias: &str, what: &str| {
        tracing::warn!("{family}: key {alias} skipped: {what}");
    };
    let der = match driver.certificate(card, &slot) {
        Ok(Some(der)) => der,
        Ok(None) => {
            tracing::info!("{family}: key {} has no certificate", slot.alias);
            return Ok(None);
        }
        Err(e @ (TokenError::Malformed(_) | TokenError::Card { .. })) => {
            skipped(&slot.alias, &e.to_string());
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let cert = match Certificate::from_der(&der) {
        Ok(cert) => cert,
        Err(e) => {
            skipped(&slot.alias, &format!("certificate: {e}"));
            return Ok(None);
        }
    };
    let public = match driver.public_key(card, &slot) {
        Ok(public) => public,
        Err(e @ (TokenError::Malformed(_) | TokenError::Card { .. })) => {
            skipped(&slot.alias, &e.to_string());
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    match PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info()) {
        Ok(certified) if certified == public => Ok(Some((slot, public, cert))),
        _ => {
            skipped(&slot.alias, "the certificate is another key's");
            Ok(None)
        }
    }
}

/// A key on a token: signs in a transaction of its own, after checking that the same token
/// is in the reader.
pub(crate) struct CardKey {
    backend: Arc<dyn Backend>,
    reader: String,
    kind: TokenKind,
    token_id: String,
    slot: KeySlot,
    public: PublicKey,
    pin: Zeroizing<String>,
    /// The token refused the PIN: it is not sent again.
    pin_rejected: AtomicBool,
    trace: bool,
}

const PIN_REFUSED: &str = "the token refused the PIN";

impl CardKey {
    fn sign_on_card(&self, alg: SigAlg, data: &[u8]) -> Result<Vec<u8>, TokenError> {
        let mut conn = connect(&*self.backend, &self.reader, self.kind).map_err(|e| match e {
            TokenError::NoDevice => TokenError::WrongCard,
            e => e,
        })?;
        in_transaction(&mut *conn, |conn| {
            let mut card = Card::new(conn, self.trace);
            let mut driver = open_driver(self.kind, &mut card)?;
            if driver.token_id() != self.token_id {
                return Err(TokenError::WrongCard);
            }
            driver.verify_pin(&mut card, &self.pin)?;
            let sig = driver.sign(&mut card, &self.slot, alg, data);
            logout(&mut *driver, &mut card);
            sig
        })
    }
}

impl TokenSigner for CardKey {
    fn alg(&self) -> KeyAlg {
        self.slot.alg
    }

    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_digest(&self, alg: SigAlg, digest: &[u8]) -> Result<Vec<u8>, KeyError> {
        if self.pin_rejected.load(Ordering::SeqCst) {
            return Err(KeyError::Token(PIN_REFUSED.to_owned()));
        }
        let data = match self.slot.alg {
            KeyAlg::Rsa => digest_info(alg, digest)?,
            KeyAlg::Gost2004 | KeyAlg::Gost2015_512 => digest.to_vec(),
        };
        self.sign_on_card(alg, &data).map_err(|e| match e {
            TokenError::WrongPin { .. } | TokenError::PinBlocked | TokenError::InvalidPin => {
                self.pin_rejected.store(true, Ordering::SeqCst);
                KeyError::Token(PIN_REFUSED.to_owned())
            }
            TokenError::WrongCard => KeyError::Token("another token is in the reader".to_owned()),
            e => KeyError::Token(e.to_string()),
        })
    }

    fn describe(&self) -> String {
        format!(
            "{} in {}, {}",
            self.kind.storage_name(),
            self.reader,
            self.slot.alias
        )
    }
}
