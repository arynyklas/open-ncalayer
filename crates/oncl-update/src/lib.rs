//! OpenNCALayer's self-update logic, without windows or a network stack of its own:
//!
//! - [`index`]: the update index of a channel (`updates/v1/<channel>.json`), its model and
//!   structural checks, and the sha256 check of a downloaded package;
//! - [`contents_sha256()`]: the sum of the files in a package, which a full package rebuilt
//!   from a delta is checked against;
//! - [`verify()`]: the minisign signature of an index (`<channel>.json.minisig`), its trusted
//!   comment, the `seq` against the last one seen and the index's age;
//! - [`choose()`]: the version to move to, with the staged rollout, revoked versions and
//!   versions that failed locally;
//! - [`state`]: `<data>/update/state.json`, what the updater keeps between runs;
//! - [`fetch()`]: the index and its signature, through an [`HttpTransport`];
//! - [`embedded_keys()`]: the public keys built in (`keys/current.pub`, `keys/next.pub`).
//!
//! The format is described in `docs/design/update-index.md`.
//!
//! [`HttpTransport`]: oncl_pki::http::HttpTransport

pub mod choose;
mod contents;
pub mod fetch;
mod hex;
pub mod index;
mod keys;
pub mod plugins;
pub mod state;
pub mod verify;

pub use choose::{Choice, Target, choose, rollout_bucket};
pub use contents::contents_sha256;
pub use fetch::{Fetched, fetch, index_url};
pub use index::{
    Asset, Channel, CoreRelease, Extension, Flavor, FlavorPackage, Index, Package, Sha256,
};
pub use keys::embedded_keys;
pub use minisign_verify::PublicKey;
pub use plugins::{
    PluginChoice, PluginName, PluginRelease, PluginReplaces, choose_plugin, offer, plugin_bucket,
};
pub use semver::Version;
pub use state::{PendingHealth, State};
pub use verify::{MAX_AGE, MAX_INDEX_LEN, trusted_comment, verify};

use time::OffsetDateTime;

/// Why an index, its signature or a package is refused.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The index is bigger than [`MAX_INDEX_LEN`].
    #[error("the update index is larger than {MAX_INDEX_LEN} bytes")]
    TooLarge,
    /// The signature file is not a minisign signature.
    #[error("the update index signature is malformed")]
    MalformedSignature,
    /// No trusted key made the signature, or the index or its trusted comment were changed
    /// after signing; also a signature in minisign's legacy (not prehashed) mode.
    #[error("the update index signature does not match any trusted key")]
    BadSignature,
    /// The signed trusted comment is not `channel=…;seq=…`.
    #[error("the update index signature's trusted comment is malformed: {0}")]
    BadTrustedComment(String),
    /// The signed trusted comment names another channel or `seq` than the index.
    #[error("the update index signature is for {comment}, the index is {index}")]
    CommentMismatch {
        /// `channel=…;seq=…` of the trusted comment.
        comment: String,
        /// `channel=…;seq=…` of the index.
        index: String,
    },
    /// The index is not valid JSON of the expected shape, or breaks a rule of the format.
    #[error("the update index is malformed: {0}")]
    Malformed(String),
    /// The index uses a `schema` this version does not read.
    #[error("the update index schema {0} is not supported")]
    UnsupportedSchema(u32),
    /// The index is of another channel than the one asked for.
    #[error("the update index is for the {found} channel, not {expected}")]
    WrongChannel {
        /// The channel asked for.
        expected: Channel,
        /// The channel of the index.
        found: Channel,
    },
    /// The index is older than one already seen: `seq` went back.
    #[error("the update index seq {seq} is older than the last seen {last}")]
    Rollback {
        /// `seq` of the index.
        seq: u64,
        /// The last `seq` seen.
        last: u64,
    },
    /// The index is past its `expires`, or older than [`MAX_AGE`].
    #[error("the update index expired at {0}")]
    Expired(OffsetDateTime),
    /// A downloaded package has another size than the index says.
    #[error("the package is {actual} bytes, the update index says {expected}")]
    PackageSize {
        /// The size in the index.
        expected: u64,
        /// The size of the file.
        actual: u64,
    },
    /// A downloaded package has another sha256 than the index says.
    #[error("the package's sha256 does not match the update index")]
    PackageHash,
    /// A package rebuilt from a delta holds other files than the index's full package
    /// ([`contents_sha256()`]), or is not a package.
    #[error("the package's contents do not match the update index: {0}")]
    PackageContents(String),
    /// The index could not be downloaded: no response, a status other than 200 or 404, or a
    /// URL that is not HTTPS.
    #[error("the update index could not be downloaded: {0}")]
    Fetch(String),
    /// The index of the channel is not published (404): nothing has been released into it
    /// yet.
    #[error("the {0} channel has no update index yet")]
    NotPublished(Channel),
    /// A file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A built-in public key is not a minisign public key.
    #[error("a built-in update signing key is malformed: {0}")]
    BadKey(String),
}
