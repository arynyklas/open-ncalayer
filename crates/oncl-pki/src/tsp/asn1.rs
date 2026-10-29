//! ASN.1 structures of RFC 3161. They borrow from the DER input; the TSA's answer is
//! decoded strictly (DER), after `ber::to_der` normalization.

use crate::asn1util::{RawGeneralizedTime, RawSequence};
use der::Sequence;
use der::asn1::{AnyRef, BitStringRef, IntRef, ObjectIdentifier, OctetStringRef, UintRef};
use spki::AlgorithmIdentifierRef;

/// `MessageImprint`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: &'a OctetStringRef,
}

/// `TimeStampReq`. The nonce is an INTEGER; only our requests use this structure, and their
/// nonces are never negative.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TimeStampReq<'a> {
    pub version: u8,
    pub message_imprint: MessageImprint<'a>,
    pub req_policy: Option<ObjectIdentifier>,
    pub nonce: Option<UintRef<'a>>,
    /// `DEFAULT FALSE`.
    pub cert_req: Option<bool>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<RawSequence<'a>>,
}

/// `TimeStampResp`; the token is a `ContentInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TimeStampResp<'a> {
    pub status: PkiStatusInfo<'a>,
    pub time_stamp_token: Option<AnyRef<'a>>,
}

/// `PKIStatusInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct PkiStatusInfo<'a> {
    pub status: i64,
    pub status_string: Option<RawSequence<'a>>,
    pub fail_info: Option<BitStringRef<'a>>,
}

/// `TSTInfo`. The nonce is an INTEGER and may be negative: other clients' TSAs echo
/// whatever their requests carried (Kalkan's are signed random numbers).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TstInfo<'a> {
    pub version: u8,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: IntRef<'a>,
    pub gen_time: RawGeneralizedTime<'a>,
    pub accuracy: Option<RawSequence<'a>>,
    /// `DEFAULT FALSE`.
    pub ordering: Option<bool>,
    pub nonce: Option<IntRef<'a>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<RawSequence<'a>>,
}
