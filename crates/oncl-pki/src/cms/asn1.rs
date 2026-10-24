//! ASN.1 structures of CMS (RFC 5652) and ESS (RFC 5035) used by the signer and the
//! verifier.
//!
//! The structures borrow from the DER input, so a document is not copied while it is
//! parsed. Every `SET OF` stays raw ([`RawSet`]) in stored order: a co-signature keeps the
//! existing digest algorithms, certificates and signers byte for byte, and `ber::to_der`
//! keeps the (possibly non-DER) element order of BER input.

use der::asn1::{AnyRef, Int, ObjectIdentifier, OctetStringRef};
use der::{
    DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, SliceReader, Tag,
    TagMode, TagNumber, Writer,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::name::Name;

/// Contents of a `SET OF` (or of an `IMPLICIT` tagged one), raw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawSet<'a>(pub &'a [u8]);

impl<'a> RawSet<'a> {
    /// Encoded elements (full TLVs) in stored order.
    pub fn tlvs(self) -> der::Result<Vec<&'a [u8]>> {
        let mut reader = SliceReader::new(self.0)?;
        let mut out = Vec::new();
        while !reader.is_finished() {
            out.push(reader.tlv_bytes()?);
        }
        Ok(out)
    }
}

impl<'a> DecodeValue<'a> for RawSet<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_slice(header.length()).map(RawSet)
    }
}

impl EncodeValue for RawSet<'_> {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(self.0.len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(self.0)
    }
}

impl FixedTag for RawSet<'_> {
    const TAG: Tag = Tag::Set;
}

/// Concatenated DER `SET OF` contents: the elements sorted by their encodings.
pub(crate) fn der_set_contents(mut elements: Vec<Vec<u8>>) -> Vec<u8> {
    elements.sort();
    elements.concat()
}

/// `ContentInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: AnyRef<'a>,
}

/// `ContentInfo { id-signedData, [0] EXPLICIT SignedData }` for encoding without copying the
/// `SignedData` into an intermediate buffer.
pub(crate) struct SignedContentInfo<'s, 'a> {
    pub signed_data: &'s SignedData<'a>,
}

impl SignedContentInfo<'_, '_> {
    fn explicit(&self) -> der::asn1::ContextSpecificRef<'_, SignedData<'_>> {
        der::asn1::ContextSpecificRef {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: self.signed_data,
        }
    }
}

impl EncodeValue for SignedContentInfo<'_, '_> {
    fn value_len(&self) -> der::Result<Length> {
        crate::oid::SIGNED_DATA.encoded_len()? + self.explicit().encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        crate::oid::SIGNED_DATA.encode(writer)?;
        self.explicit().encode(writer)
    }
}

impl FixedTag for SignedContentInfo<'_, '_> {
    const TAG: Tag = Tag::Sequence;
}

/// `SignedData`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: RawSet<'a>,
    pub encap_content_info: EncapsulatedContentInfo<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<RawSet<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RawSet<'a>>,
    pub signer_infos: RawSet<'a>,
}

/// `EncapsulatedContentInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct EncapsulatedContentInfo<'a> {
    pub e_content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub e_content: Option<&'a OctetStringRef>,
}

/// `SignerInfo`; `sid` is the raw `SignerIdentifier` CHOICE and `signed_attrs` the raw
/// contents of the `[0] IMPLICIT SET OF Attribute` (verified over with the `SET` tag).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct SignerInfo<'a> {
    pub version: u8,
    pub sid: AnyRef<'a>,
    pub digest_algorithm: AlgorithmIdentifierRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signed_attrs: Option<RawSet<'a>>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: &'a OctetStringRef,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub unsigned_attrs: Option<RawSet<'a>>,
}

/// `IssuerAndSerialNumber`.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: Int,
}

/// `Attribute`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct Attribute<'a> {
    pub attr_type: ObjectIdentifier,
    pub attr_values: RawSet<'a>,
}

/// `SigningCertificateV2`.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct SigningCertificateV2<'a> {
    pub certs: Vec<EssCertIdV2<'a>>,
    pub policies: Option<AnyRef<'a>>,
}

/// `ESSCertIDv2`; an absent `hash_algorithm` means SHA-256.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct EssCertIdV2<'a> {
    pub hash_algorithm: Option<AlgorithmIdentifierRef<'a>>,
    pub cert_hash: &'a OctetStringRef,
    pub issuer_serial: Option<AnyRef<'a>>,
}
