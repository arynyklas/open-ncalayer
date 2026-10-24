//! ASN.1 structures of RFC 3161. They borrow from the DER input; the TSA's answer is
//! decoded strictly (DER), after `ber::to_der` normalization.

use der::asn1::{AnyRef, BitStringRef, IntRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Writer};
use spki::AlgorithmIdentifierRef;

/// A value of a fixed tag kept as its raw contents.
macro_rules! raw_value {
    ($(#[$doc:meta])* $name:ident, $tag:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name<'a>(pub &'a [u8]);

        impl<'a> DecodeValue<'a> for $name<'a> {
            type Error = der::Error;

            fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
                reader.read_slice(header.length()).map($name)
            }
        }

        impl EncodeValue for $name<'_> {
            fn value_len(&self) -> der::Result<Length> {
                Length::try_from(self.0.len())
            }

            fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
                writer.write(self.0)
            }
        }

        impl FixedTag for $name<'_> {
            const TAG: Tag = $tag;
        }
    };
}

raw_value!(
    /// Contents of a `SEQUENCE` (or of an `IMPLICIT` tagged one), raw.
    RawSequence,
    Tag::Sequence
);
raw_value!(
    /// Contents of a `GeneralizedTime`, raw: RFC 3161 allows fractions of a second in
    /// genTime, which `der::asn1::GeneralizedTime` refuses.
    RawGeneralizedTime,
    Tag::GeneralizedTime
);

/// `MessageImprint`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: &'a OctetStringRef,
}

/// `TimeStampReq`.
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

/// `TSTInfo`. The nonce is unsigned: a negative one is malformed.
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
    pub nonce: Option<UintRef<'a>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<RawSequence<'a>>,
}
