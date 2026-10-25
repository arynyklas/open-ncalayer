//! ASN.1 structures of RFC 6960. They borrow from the DER input; the responder's answer is
//! decoded strictly (DER), after `ber::to_der` normalization. CHOICEs (`ResponderID`,
//! `CertStatus`) stay [`AnyRef`] and are told apart by their tag in `ocsp`.

use crate::tsp::asn1::{RawGeneralizedTime, RawSequence};
use der::asn1::{AnyRef, BitStringRef, IntRef, ObjectIdentifier, OctetStringRef};
use der::{
    DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Sequence, Tag, Writer,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::Certificate;

/// An `ENUMERATED` of 0 to 127: `OCSPResponseStatus` and `CRLReason` have no larger value,
/// anything else is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Enumerated(pub u8);

impl<'a> DecodeValue<'a> for Enumerated {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        match reader.read_slice(header.length())? {
            &[value] if value < 0x80 => Ok(Enumerated(value)),
            _ => Err(reader.error(ErrorKind::Value {
                tag: Tag::Enumerated,
            })),
        }
    }
}

impl EncodeValue for Enumerated {
    fn value_len(&self) -> der::Result<Length> {
        Ok(Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write_byte(self.0)
    }
}

impl FixedTag for Enumerated {
    const TAG: Tag = Tag::Enumerated;
}

/// `CertID`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct CertId<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub issuer_name_hash: &'a OctetStringRef,
    pub issuer_key_hash: &'a OctetStringRef,
    pub serial_number: IntRef<'a>,
}

/// `Request`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct Request<'a> {
    pub req_cert: CertId<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub single_request_extensions: Option<RawSequence<'a>>,
}

/// `TBSRequest`; `version` is `DEFAULT v1`.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct TbsRequest<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub requestor_name: Option<AnyRef<'a>>,
    pub request_list: Vec<Request<'a>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub request_extensions: Option<RawSequence<'a>>,
}

/// `OCSPRequest`.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct OcspRequest<'a> {
    pub tbs_request: TbsRequest<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub optional_signature: Option<RawSequence<'a>>,
}

/// `OCSPResponse`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct OcspResponse<'a> {
    pub response_status: Enumerated,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

/// `ResponseBytes`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct ResponseBytes<'a> {
    pub response_type: ObjectIdentifier,
    pub response: &'a OctetStringRef,
}

/// `BasicOCSPResponse`; `tbs_response_data` stays whole, as it is signed.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct BasicOcspResponse<'a> {
    pub tbs_response_data: AnyRef<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub certs: Option<Vec<Certificate>>,
}

/// `ResponseData`; `version` is `DEFAULT v1`. The responder ID is `[1] EXPLICIT Name` or
/// `[2] EXPLICIT KeyHash`.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct ResponseData<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    pub responder_id: AnyRef<'a>,
    pub produced_at: RawGeneralizedTime<'a>,
    pub responses: Vec<SingleResponse<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub response_extensions: Option<RawSequence<'a>>,
}

/// `SingleResponse`. The status is `[0] IMPLICIT NULL` (good), `[1] IMPLICIT RevokedInfo`
/// or `[2] IMPLICIT NULL` (unknown).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub cert_status: AnyRef<'a>,
    pub this_update: RawGeneralizedTime<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub next_update: Option<RawGeneralizedTime<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub single_extensions: Option<RawSequence<'a>>,
}

/// `RevokedInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct RevokedInfo<'a> {
    pub revocation_time: RawGeneralizedTime<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub revocation_reason: Option<Enumerated>,
}
