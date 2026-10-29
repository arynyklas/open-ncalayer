//! Token families, their Kalkan storage names and their ATRs.

use hex_literal::hex;

/// A token family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// Kaztoken.
    Kaztoken,
    /// Kazakhstan ID card.
    KzIdCard,
    /// eToken PRO 72K (Java).
    EToken72K,
    /// eToken 5110 (Gamma applet).
    EToken5110,
    /// JaCarta (Gamma applet).
    JaCarta,
    /// AKey.
    AKey,
}

/// The ATR of every supported token, matched exactly.
pub const ATRS: &[(TokenKind, &[u8])] = &[
    (TokenKind::KzIdCard, &hex!("3b771800004b4153414b4944")),
    (TokenKind::KzIdCard, &hex!("3b391900534f4d414453333031")),
    (TokenKind::KzIdCard, &hex!("3b391900534f4d414453333033")),
    (
        TokenKind::KzIdCard,
        &hex!("3b3e9500534f4d412d633030372d44533161"),
    ),
    (
        TokenKind::KzIdCard,
        &hex!("3b3e9500534f4d412d633030372d44533162"),
    ),
    (
        TokenKind::KzIdCard,
        &hex!("3bfa130000900131fe450031807394410000900075"),
    ),
    (
        TokenKind::KzIdCard,
        &hex!("3bfa1800ff8031fe450031807394410000900090"),
    ),
    (TokenKind::Kaztoken, &hex!("3b88014b415a544f4b454e82")),
    (TokenKind::Kaztoken, &hex!("3b9896004b415a544f4b454e")),
    (TokenKind::Kaztoken, &hex!("3b8880014b5453437781832053")),
    (TokenKind::EToken72K, &hex!("3bd518008131fe7d8073c82110f4")),
    (
        TokenKind::JaCarta,
        &hex!("3bdc18ff8191fe1fc38073c821136601061159000128"),
    ),
    (
        TokenKind::AKey,
        &hex!("3bfc180000813180459067464a00643170c172fee0e2"),
    ),
    (
        TokenKind::AKey,
        &hex!("3bfc180000813180459067464a01037206000000001c"),
    ),
    (
        TokenKind::AKey,
        &hex!("3bfc180000813180459067464a010359040000000035"),
    ),
    (TokenKind::AKey, &hex!("3b9095801f0399")),
    (TokenKind::EToken5110, &hex!("3bd5180081313a7d8073c8211030")),
    (
        TokenKind::EToken5110,
        &hex!("3b7f96000080318065b0844150f6120ffe829000"),
    ),
];

impl TokenKind {
    /// Every family, in the order of Kalkan's storages.
    pub const ALL: [TokenKind; 6] = [
        TokenKind::Kaztoken,
        TokenKind::KzIdCard,
        TokenKind::EToken72K,
        TokenKind::EToken5110,
        TokenKind::JaCarta,
        TokenKind::AKey,
    ];

    /// Kalkan's storage name of the family.
    pub fn storage_name(self) -> &'static str {
        match self {
            TokenKind::Kaztoken => "AKKaztokenStore",
            TokenKind::KzIdCard => "AKKZIDCardStore",
            TokenKind::EToken72K => "AKEToken72KStore",
            TokenKind::EToken5110 => "AKEToken5110Store",
            TokenKind::JaCarta => "AKJaCartaStore",
            TokenKind::AKey => "AKAKEYStore",
        }
    }

    /// The family of a storage name (exact match).
    pub fn from_storage_name(name: &str) -> Option<TokenKind> {
        TokenKind::ALL
            .into_iter()
            .find(|k| k.storage_name() == name)
    }

    /// The family of an ATR (exact match against [`ATRS`]).
    pub fn from_atr(atr: &[u8]) -> Option<TokenKind> {
        ATRS.iter().find(|(_, a)| *a == atr).map(|(k, _)| *k)
    }

    /// The token tells how many PIN tries are left.
    pub fn reports_tries(self) -> bool {
        matches!(
            self,
            TokenKind::Kaztoken | TokenKind::KzIdCard | TokenKind::AKey
        )
    }
}
