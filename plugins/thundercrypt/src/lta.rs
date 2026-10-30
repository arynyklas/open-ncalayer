//! CAdES B-T → B-LT → B-LTA (ETSI EN 319 122-1) of a CMS with one signer, in DER: the
//! certificate and revocation values go into SignedData (`certificates`; `crls` with the OCSP
//! answer as an `id-ri-ocsp-response` choice and the CRLs), then an
//! `archive-time-stamp-v3` whose token carries the `ats-hash-index-v3` of the archived
//! fields. Hashes are GOST 34.11-2015 (512) (the core's `hash`), the time-stamp is the
//! default TSA's (`tsp_request`).

/// id-ri-ocsp-response.
const OCSP_RESPONSE_FORMAT: &str = "1.3.6.1.5.5.7.16.2";
/// id-aa-ets-archiveTimestampV3.
pub const ARCHIVE_TIME_STAMP_V3: &str = "0.4.0.1733.2.4";
/// id-aa-ATSHashIndex-v3.
pub const ATS_HASH_INDEX_V3: &str = "0.4.0.19122.1.5";
/// GOST 34.11-2015 (512).
const STREEBOG_512: &str = "1.2.398.3.10.1.3.3";

/// A DER TLV: its tag, the whole TLV and its content.
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub whole: &'a [u8],
    pub content: &'a [u8],
}

/// The TLVs of `der`, one after the other.
pub fn tlvs(mut der: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let bad = || "malformed DER".to_owned();
        let tag = der[0];
        let first = *der.get(1).ok_or_else(bad)?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return Err(bad());
            }
            let bytes = der.get(2..2 + n).ok_or_else(bad)?;
            (
                bytes
                    .iter()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
                2 + n,
            )
        };
        let end = header
            .checked_add(len)
            .filter(|e| *e <= der.len())
            .ok_or_else(bad)?;
        out.push(Tlv {
            tag,
            whole: &der[..end],
            content: &der[header..end],
        });
        der = &der[end..];
    }
    Ok(out)
}

/// The TLVs inside the only TLV of `der`.
pub fn inside(der: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let outer = tlvs(der)?;
    let first = outer.first().ok_or("empty DER")?;
    tlvs(first.content)
}

/// A TLV of `tag` around `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A DER OBJECT IDENTIFIER of the dotted `oid`.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').filter_map(|a| a.parse().ok()).collect();
    let mut content = Vec::new();
    let mut push = |mut arc: u64| {
        let mut bytes = vec![(arc & 0x7f) as u8];
        arc >>= 7;
        while arc > 0 {
            bytes.push(0x80 | (arc & 0x7f) as u8);
            arc >>= 7;
        }
        bytes.reverse();
        content.extend(bytes);
    };
    push(arcs[0] * 40 + arcs.get(1).copied().unwrap_or(0));
    for arc in arcs.iter().skip(2) {
        push(*arc);
    }
    tlv(0x06, &content)
}

/// A DER SET (or `[n]` of SET OF semantics, tag `tag`) of `items`, sorted as DER sorts them.
pub fn set_of(tag: u8, mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort();
    items.dedup();
    tlv(tag, &items.concat())
}

/// An attribute `oid` of one value.
pub fn attribute(oid_dotted: &str, value: &[u8]) -> Vec<u8> {
    tlv(
        0x30,
        &[oid(oid_dotted), set_of(0x31, vec![value.to_vec()])].concat(),
    )
}

/// `der` (a ContentInfo{SignedData}) rebuilt by `edit` on the SignedData's items.
pub fn edit_signed_data(
    der: &[u8],
    edit: impl FnOnce(Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, String>,
) -> Result<Vec<u8>, String> {
    let info = inside(der)?;
    let [content_type, explicit] = info.as_slice() else {
        return Err("not a ContentInfo".to_owned());
    };
    let items: Vec<Vec<u8>> = inside(explicit.content)?
        .iter()
        .map(|t| t.whole.to_vec())
        .collect();
    let signed = tlv(0x30, &edit(items)?.concat());
    Ok(tlv(
        0x30,
        &[content_type.whole.to_vec(), tlv(0xa0, &signed)].concat(),
    ))
}

/// The first signer info of the SignedData `items` rebuilt with `unsigned` added to its
/// unsigned attributes.
pub fn add_unsigned(items: &mut [Vec<u8>], unsigned: Vec<u8>) -> Result<(), String> {
    let infos = items.last_mut().ok_or("no signer infos")?;
    let signers = inside(infos)?;
    let first = signers.first().ok_or("no signer")?;
    let parts = tlvs(first.content)?;
    let mut fields: Vec<Vec<u8>> = parts
        .iter()
        .filter(|t| t.tag != 0xa1)
        .map(|t| t.whole.to_vec())
        .collect();
    let mut attrs: Vec<Vec<u8>> = match parts.iter().find(|t| t.tag == 0xa1) {
        Some(old) => tlvs(old.content)?
            .iter()
            .map(|t| t.whole.to_vec())
            .collect(),
        None => Vec::new(),
    };
    attrs.push(unsigned);
    fields.push(set_of(0xa1, attrs));
    let mut all: Vec<Vec<u8>> = vec![tlv(0x30, &fields.concat())];
    all.extend(signers.iter().skip(1).map(|t| t.whole.to_vec()));
    *infos = set_of(0x31, all);
    Ok(())
}

/// What the upgrade adds.
pub struct Values<'a> {
    /// Certificates (the chain), DER.
    pub certificates: &'a [Vec<u8>],
    /// OCSP responses, DER.
    pub ocsp: &'a [Vec<u8>],
    /// CRLs, DER.
    pub crls: &'a [Vec<u8>],
}

/// The CMS with the certificate and revocation values added (B-LT).
pub fn with_values(cms: &[u8], values: &Values) -> Result<Vec<u8>, String> {
    edit_signed_data(cms, |items| {
        let mut out = Vec::new();
        let mut certs: Vec<Vec<u8>> = Vec::new();
        let mut crls: Vec<Vec<u8>> = Vec::new();
        let mut rest = Vec::new();
        for (i, item) in items.into_iter().enumerate() {
            match item[0] {
                0xa0 if i > 2 => certs.extend(inside(&item)?.iter().map(|t| t.whole.to_vec())),
                0xa1 if i > 2 => crls.extend(inside(&item)?.iter().map(|t| t.whole.to_vec())),
                _ if i < 3 => out.push(item),
                _ => rest.push(item),
            }
        }
        certs.extend(values.certificates.iter().cloned());
        crls.extend(values.crls.iter().cloned());
        for response in values.ocsp {
            crls.push(tlv(
                0xa1,
                &[oid(OCSP_RESPONSE_FORMAT), response.clone()].concat(),
            ));
        }
        out.push(set_of(0xa0, certs));
        if !crls.is_empty() {
            out.push(set_of(0xa1, crls));
        }
        out.extend(rest);
        Ok(out)
    })
}

/// A digest of some bytes, or why not.
pub type Hasher<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

/// The `ATSHashIndexV3` of the signer of `cms`, with `hash` (GOST 34.11-2015 (512)).
pub fn hash_index(cms: &[u8], hash: Hasher<'_>) -> Result<Vec<u8>, String> {
    let items = signed_items(cms)?;
    let hashes = |tag: u8| -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        if let Some(field) = items.iter().skip(3).find(|t| t.tag == tag) {
            for element in tlvs(field.content)? {
                out.push(tlv(0x04, &hash(element.whole)?));
            }
        }
        Ok(tlv(0x30, &out.concat()))
    };
    let signer = first_signer(&items)?;
    // One hash per value of each unsigned attribute: its attrType followed by that value
    // (EN 319 122-1 §5.5.2).
    let mut unsigned = Vec::new();
    if let Some(attrs) = signer.iter().find(|t| t.tag == 0xa1) {
        for attr in tlvs(attrs.content)? {
            let parts = tlvs(attr.content)?;
            let attr_type = parts.first().ok_or("malformed attribute")?;
            let values = parts.get(1).ok_or("malformed attribute")?;
            for value in tlvs(values.content)? {
                let input = [attr_type.whole, value.whole].concat();
                unsigned.push(tlv(0x04, &hash(&input)?));
            }
        }
    }
    Ok(tlv(
        0x30,
        &[
            tlv(0x30, &[oid(STREEBOG_512), vec![0x05, 0x00]].concat()),
            hashes(0xa0)?,
            hashes(0xa1)?,
            tlv(0x30, &unsigned.concat()),
        ]
        .concat(),
    ))
}

/// What the archive time-stamp's imprint is computed over: eContentType, the hash of the
/// content, the signer's version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm and
/// signature, and the `ATSHashIndexV3`.
pub fn imprint_input(cms: &[u8], content_hash: &[u8], index: &[u8]) -> Result<Vec<u8>, String> {
    let items = signed_items(cms)?;
    let encap = tlvs(items.get(2).ok_or("no content info")?.content)?;
    let mut out = encap.first().ok_or("no eContentType")?.whole.to_vec();
    out.extend_from_slice(content_hash);
    for field in first_signer(&items)?.iter().filter(|t| t.tag != 0xa1) {
        out.extend_from_slice(field.whole);
    }
    out.extend_from_slice(index);
    Ok(out)
}

/// The time-stamp token with its `ats-hash-index-v3`.
pub fn token_with_index(token: &[u8], index: &[u8]) -> Result<Vec<u8>, String> {
    edit_signed_data(token, |mut items| {
        add_unsigned(&mut items, attribute(ATS_HASH_INDEX_V3, index))?;
        Ok(items)
    })
}

/// The CMS with the `archive-time-stamp-v3` of `token` on its signer (B-LTA).
pub fn with_archive_time_stamp(cms: &[u8], token: &[u8]) -> Result<Vec<u8>, String> {
    edit_signed_data(cms, |mut items| {
        add_unsigned(&mut items, attribute(ARCHIVE_TIME_STAMP_V3, token))?;
        Ok(items)
    })
}

/// The items of the SignedData of `cms`.
fn signed_items(cms: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let info = inside(cms)?;
    let explicit = info.get(1).ok_or("not a ContentInfo")?;
    inside(explicit.content)
}

/// The fields of the first signer info.
fn first_signer<'a>(items: &[Tlv<'a>]) -> Result<Vec<Tlv<'a>>, String> {
    let infos = items.last().ok_or("no signer infos")?;
    let first = *tlvs(infos.content)?.first().ok_or("no signer")?;
    tlvs(first.content)
}
