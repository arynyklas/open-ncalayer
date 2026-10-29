//! Software cards for tests and the end-to-end daemon: each family's applet answers exactly
//! the commands its driver sends, with the synthetic keys of the test PKI. Never in release
//! builds.

mod applet;
mod backend;
mod config;
mod etoken72k;
mod kaztoken;
mod kzid;
pub mod soft;
mod vpcd;

pub use backend::{EmulatorBackend, Exchange, TransactionGuard};
pub use config::{ReaderConfig, read_config};
pub use vpcd::{VPCD_PORT, serve_vpcd};

use crate::backend::Protocol;
use crate::drivers::IdCardInfo;
use crate::kind::{ATRS, TokenKind};
use oncl_pki::pkcs12::KeyEntry;
use std::path::Path;

/// A card as the reader sees it: an ATR and APDUs in, responses out.
pub trait SoftCard: Send {
    /// ATR of the card.
    fn atr(&self) -> Vec<u8>;
    /// Protocol the card speaks.
    fn protocol(&self) -> Protocol;
    /// Response (data and status word) to a command APDU.
    fn process(&mut self, apdu: &[u8]) -> Vec<u8>;
    /// Card reset: the PIN is no longer verified, no applet is selected.
    fn reset(&mut self);
}

/// A software key held by an emulated card: a synthetic key with its certificate.
#[derive(Clone, Debug)]
pub struct EmuKey {
    /// The key and its certificate.
    pub entry: KeyEntry,
}

impl EmuKey {
    /// The first key of a PKCS#12 file.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or holds no key.
    pub fn load(p12: &Path, password: &str) -> Result<EmuKey, String> {
        let bytes = std::fs::read(p12).map_err(|e| format!("{}: {e}", p12.display()))?;
        let entry = oncl_pki::pkcs12::load(&bytes, password)
            .map_err(|e| format!("{}: {e}", p12.display()))?
            .into_iter()
            .next()
            .ok_or_else(|| format!("{}: no key", p12.display()))?;
        Ok(EmuKey { entry })
    }
}

/// What an emulated card holds and how it behaves.
#[derive(Clone, Debug)]
pub struct CardSpec {
    /// Family.
    pub kind: TokenKind,
    /// Which of the family's ATRs ([`ATRS`]) the card has.
    pub atr_index: usize,
    /// Protocol.
    pub protocol: Protocol,
    /// Serial number.
    pub serial: [u8; 8],
    /// PIN.
    pub pin: String,
    /// PIN tries left.
    pub tries: u8,
    /// PIN tries after a correct PIN.
    pub max_tries: u8,
    /// Keys, in the card's order.
    pub keys: Vec<EmuKey>,
    /// Fixed GOST nonce `k` (big-endian), for signatures equal to the software ones.
    pub fixed_k: Option<Vec<u8>>,
    /// T=0 behaviour: data of a command without Le comes through `61xx` and GET RESPONSE, a
    /// wrong Le is answered `6Cxx`.
    pub t0_quirks: bool,
    /// Test mode: GOST signatures come with their halves swapped.
    pub swap_signature_halves: bool,
    /// Holder data of an ID card.
    pub id_card: Option<IdCardInfo>,
    /// Certificates are stored as raw DER rather than gzip.
    pub raw_certificates: bool,
    /// An ID card of 2020: key references with bit 7 set are refused (`6A80`).
    pub id_card_2020: bool,
    /// An ID card whose certificate EF `0101` holds the certificate of the first RSA key
    /// instead of the first GOST key's.
    pub id_card_rsa_cert_first: bool,
}

impl CardSpec {
    /// A card of `kind` with `pin` (10 tries) and `keys`: the family's first ATR, its usual
    /// protocol (T=0 with its quirks for the ID card, else T=1), serial `01…08`.
    pub fn new(kind: TokenKind, pin: &str, keys: Vec<EmuKey>) -> CardSpec {
        let t0 = kind == TokenKind::KzIdCard;
        CardSpec {
            kind,
            atr_index: 0,
            protocol: if t0 { Protocol::T0 } else { Protocol::T1 },
            serial: [1, 2, 3, 4, 5, 6, 7, 8],
            pin: pin.to_owned(),
            tries: 10,
            max_tries: 10,
            keys,
            fixed_k: None,
            t0_quirks: t0,
            swap_signature_halves: false,
            id_card: None,
            raw_certificates: false,
            id_card_2020: false,
            id_card_rsa_cert_first: false,
        }
    }

    /// The card's ATR.
    ///
    /// # Panics
    ///
    /// If the family has no ATR of index `atr_index`.
    pub fn atr(&self) -> Vec<u8> {
        ATRS.iter()
            .filter(|(k, _)| *k == self.kind)
            .nth(self.atr_index)
            .unwrap_or_else(|| panic!("{:?} has no ATR {}", self.kind, self.atr_index))
            .1
            .to_vec()
    }
}

/// The emulated card of `spec`'s family.
///
/// # Panics
///
/// For a family without an emulated card yet.
pub fn card(spec: CardSpec) -> Box<dyn SoftCard> {
    match spec.kind {
        TokenKind::Kaztoken => {
            applet::Emulated::boxed(kaztoken::Kaztoken::new(spec.clone()), &spec)
        }
        TokenKind::KzIdCard => applet::Emulated::boxed(kzid::KzIdCard::new(spec.clone()), &spec),
        TokenKind::EToken72K => {
            applet::Emulated::boxed(etoken72k::EToken72K::new(spec.clone()), &spec)
        }
        kind => panic!("no emulated {} yet", kind.storage_name()),
    }
}
