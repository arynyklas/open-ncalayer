"""Independent bounded X04 oracle: libxml2 C14N + cryptography RSA CMS/XML math.

ETSI EN 319 132-1 V1.2.1 (2022-02) 5.3 and 5.5.2.2, non-distributed
ArchiveTimeStamp v1.4.1. No production SDK import or large-document DOM.
The direct-root synthetic RSA chain/status subset is not general PKIX, GOST,
national trust, arbitrary XAdES interoperability, or a 1-GiB/RSS certification.
"""
from __future__ import annotations
import argparse
import base64
import copy
import hashlib
import io
import platform
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_to_bytes
import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID
from lxml import etree

LIMIT = 1_048_576
DS = "http://www.w3.org/2000/09/xmldsig#"
XA = "http://uri.etsi.org/01903/v1.3.2#"
X4 = "http://uri.etsi.org/01903/v1.4.1#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENV = DS + "enveloped-signature"
NS = {"ds": DS, "x": XA, "a": X4}
NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
SHA256_OID = "2.16.840.1.101.3.4.2.1"
TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"

def bounded(path: Path) -> bytes:
    if path.stat().st_size > LIMIT:
        raise ValueError(f"oracle refuses unbounded input: {path}")
    data = path.read_bytes()
    if len(data) > LIMIT:
        raise ValueError("input grew past oracle limit")
    return data

def parse(path: Path):
    tree = etree.parse(io.BytesIO(bounded(path)), etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False))
    if tree.docinfo.doctype:
        raise ValueError("DTD not permitted")
    return tree

def decode(text: str) -> bytes:
    return base64.b64decode("".join(text.split()), validate=True)

def canonical(node) -> bytes:
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False, with_tail=False)

# Minimal independent strict DER framing of bounded CMS/TSTInfo, not a crypto
# implementation. Certificate/OCSP decoders and RSA math are cryptography.
def frames(data: bytes):
    result = []
    at = 0
    while at < len(data):
        start = at
        if at + 2 > len(data):
            raise ValueError("short DER")
        tag, length = data[at], data[at + 1]
        at += 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 8 or at + count > len(data) or data[at] == 0:
                raise ValueError("nonminimal/indefinite DER")
            length = int.from_bytes(data[at:at + count], "big")
            if length < 128:
                raise ValueError("nonminimal DER length")
            at += count
        end = at + length
        if end > len(data):
            raise ValueError("DER extent")
        result.append((tag, data[at:end], data[start:end]))
        if len(result) > 4096:
            raise ValueError("DER cardinality")
        at = end
    return result

def sequence(data: bytes):
    nodes = frames(data)
    if len(nodes) != 1 or nodes[0][0] != 0x30:
        raise ValueError("DER SEQUENCE")
    return frames(nodes[0][1])

def oid(node) -> str:
    if node[0] != 6 or not node[1]:
        raise ValueError("DER OID")
    values, value = [], 0
    for byte in node[1]:
        value = value * 128 + (byte & 127)
        if not byte & 128:
            values.append(value)
            value = 0
    if node[1][-1] & 128 or not values:
        raise ValueError("OID termination")
    first = values.pop(0)
    a = min(first // 40, 2)
    return ".".join(map(str, [a, first - 40 * a, *values]))

def integer(node) -> int:
    if node[0] != 2 or not node[1] or node[1][0] & 128:
        raise ValueError("positive DER integer required")
    return int.from_bytes(node[1], "big")

def algorithm(node) -> str:
    if node[0] != 0x30:
        raise ValueError("AlgorithmIdentifier")
    return oid(frames(node[1])[0])

def trusted_certificate(cert, root, eku=None):
    if cert.issuer != root.subject:
        raise ValueError("direct synthetic issuer mismatch")
    if not cert.not_valid_before_utc <= NOW <= cert.not_valid_after_utc:
        raise ValueError("certificate outside probe time")
    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    if eku is not None:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if eku not in usage.value:
            raise ValueError("wrong EKU")
        if eku == ExtendedKeyUsageOID.TIME_STAMPING and not usage.critical:
            raise ValueError("TSA EKU must be critical in this probe profile")

def token_math(token: bytes, root):
    content_info = sequence(token)
    if oid(content_info[0]) != "1.2.840.113549.1.7.2" or content_info[1][0] != 0xA0:
        raise ValueError("timestamp ContentInfo type")
    signed = sequence(content_info[1][1])
    if signed[1][0] != 0x31 or algorithm(frames(signed[1][1])[0]) != SHA256_OID:
        raise ValueError("CMS digestAlgorithms")
    content = frames(signed[2][1])
    if oid(content[0]) != TSTINFO_OID or content[1][0] != 0xA0:
        raise ValueError("TSTInfo eContent type")
    encapsulated = frames(content[1][1])
    if len(encapsulated) != 1 or encapsulated[0][0] != 4:
        raise ValueError("encapsulated TSTInfo")
    tst = encapsulated[0][1]
    certificates = [x509.load_der_x509_certificate(n[2]) for n in frames(signed[3][1])]
    infos = frames(signed[-1][1])
    if signed[-1][0] != 0x31 or len(infos) != 1:
        raise ValueError("timestamp signer cardinality")
    signer = frames(infos[0][1])
    sid = frames(signer[1][1])
    serial = integer(sid[1])
    matches = [c for c in certificates if c.serial_number == serial and c.issuer.public_bytes() == sid[0][2]]
    if len(matches) != 1:
        raise ValueError("CMS signer certificate association")
    cert = matches[0]
    trusted_certificate(cert, root, ExtendedKeyUsageOID.TIME_STAMPING)
    if not isinstance(cert.public_key(), rsa.RSAPublicKey) or algorithm(signer[2]) != SHA256_OID:
        raise ValueError("this independent CMS oracle requires RSA/SHA-256")
    if algorithm(signer[4]) not in {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11"} or signer[3][0] != 0xA0:
        raise ValueError("CMS signedAttrs/signature algorithm")
    attrs = {}
    for item in frames(signer[3][1]):
        fields = frames(item[1])
        key = oid(fields[0])
        if key in attrs:
            raise ValueError("duplicate CMS attribute")
        attrs[key] = frames(fields[1][1])
    if attrs["1.2.840.113549.1.9.4"][0][1] != hashlib.sha256(tst).digest():
        raise ValueError("CMS actual eContent messageDigest")
    if oid(attrs["1.2.840.113549.1.9.3"][0]) != TSTINFO_OID:
        raise ValueError("CMS actual signed content type")
    signed_attrs = bytes([0x31]) + signer[3][2][1:]
    cert.public_key().verify(signer[5][1], signed_attrs, padding.PKCS1v15(), hashes.SHA256())
    fields = sequence(tst)
    imprint = frames(fields[2][1])
    if algorithm(imprint[0]) != SHA256_OID or imprint[1][0] != 4:
        raise ValueError("TSTInfo imprint algorithm")
    if fields[4][0] != 0x18 or fields[4][1] != b"20261102120000Z":
        raise ValueError("TSTInfo actual genTime")
    nonce = next((integer(n) for n in fields[5:] if n[0] == 2), None)
    if nonce is None:
        raise ValueError("issued timestamp nonce absent")
    return imprint[1][1], cert, tst, nonce, oid(fields[1])

def signer_material(tree):
    signatures = tree.xpath("//ds:Signature", namespaces=NS)
    if len(signatures) != 1:
        raise ValueError("bounded oracle profile expects one actual RSA signer")
    signature = signatures[0]
    info = signature.find(f"{{{DS}}}SignedInfo")
    if info.find(f"{{{DS}}}CanonicalizationMethod").get("Algorithm") != EXC:
        raise ValueError("SignedInfo canonicalization")
    if info.find(f"{{{DS}}}SignatureMethod").get("Algorithm") != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
        raise ValueError("bounded oracle requires RSA document signer")
    cert = x509.load_der_x509_certificate(decode(signature.find(f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate").text))
    value = signature.find(f"{{{DS}}}SignatureValue")
    cert.public_key().verify(decode("".join(value.itertext())), canonical(info), padding.PKCS1v15(), hashes.SHA256())
    baseline_bindings(signature, info)
    return signature, info, value, cert

def baseline_bindings(signature, info):
    """EN319132-1 6.3k: ObjectReference binds Reference@Id, not URI's target."""
    data = [r for r in info.findall(f"{{{DS}}}Reference")
            if r.get("Type") != "http://uri.etsi.org/01903#SignedProperties"]
    identities = [r.get("Id") for r in data]
    if any(not identity for identity in identities) or len(set(identities)) != len(identities):
        raise ValueError("baseline data Reference identity missing/duplicate")
    properties = signature.findall(f"{{{DS}}}Object/{{{XA}}}QualifyingProperties/{{{XA}}}SignedProperties")
    if len(properties) != 1:
        raise ValueError("one signed baseline properties node required")
    containers = properties[0].findall(f"{{{XA}}}SignedDataObjectProperties")
    if len(containers) != 1:
        raise ValueError("one SignedDataObjectProperties required")
    seen = set()
    for descriptor in containers[0].findall(f"{{{XA}}}DataObjectFormat"):
        reference = descriptor.get("ObjectReference", "")
        if not reference.startswith("#"):
            raise ValueError("same-signature data Reference ObjectReference required")
        identity = unquote_to_bytes(reference[1:]).decode("utf-8", errors="strict")
        if identity not in identities or identity in seen:
            raise ValueError("foreign/target/duplicate DataObjectFormat binding")
        mime = descriptor.findall(f"{{{XA}}}MimeType")
        if len(mime) != 1 or len(mime[0]) or not (mime[0].text or "").strip():
            raise ValueError("one actual nonempty MIME type required")
        seen.add(identity)
    if seen != set(identities):
        raise ValueError("every data Reference requires its own descriptor")


def reference_bytes(tree, info):
    parts = []
    for reference in info.findall(f"{{{DS}}}Reference"):
        uri = reference.get("URI")
        if not uri.startswith("#"):
            raise ValueError("oracle profile expects same-document ID references")
        identity = unquote_to_bytes(uri[1:]).decode("utf-8", errors="strict")
        targets = tree.xpath("//*[@Id=$id]", id=identity)
        if len(targets) != 1:
            raise ValueError("missing/duplicate actual reference target")
        transforms = [t.get("Algorithm") for t in reference.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform")]
        if transforms not in ([ENV, EXC], [EXC]):
            raise ValueError("unsupported oracle reference transforms")
        # Generated fixtures sign payload outside Signature or SignedProperties;
        # the current enveloped filter removes nothing in these exact targets.
        if targets[0].xpath(".//ds:Signature", namespaces=NS):
            raise ValueError("oracle does not infer an enveloped target shortcut")
        data = canonical(targets[0])
        if reference.find(f"{{{DS}}}DigestMethod").get("Algorithm") != "http://www.w3.org/2001/04/xmlenc#sha256":
            raise ValueError("reference algorithm")
        if hashlib.sha256(data).digest() != decode(reference.find(f"{{{DS}}}DigestValue").text):
            raise ValueError("actual reference digest mismatch")
        parts.append((f"reference:{identity}", data))
    if len(parts) != 2:
        raise ValueError("payload and SignedProperties reference cardinality")
    return parts

def unsigned(signature):
    return signature.find(f"{{{DS}}}Object/{{{XA}}}QualifyingProperties/{{{XA}}}UnsignedProperties/{{{XA}}}UnsignedSignatureProperties")

def archive_parts(tree, signature, info, value, archive):
    # Independently implement EN319132-1 V1.2.1 5.5.2.2 steps 3/4/5/6.
    parts = reference_bytes(tree, info)
    parts += [("SignedInfo", canonical(info)), ("SignatureValue", canonical(value))]
    key = signature.find(f"{{{DS}}}KeyInfo")
    if key is not None:
        parts.append(("KeyInfo", canonical(key)))
    for prop in unsigned(signature):
        if prop is archive:
            break
        parts.append((etree.QName(prop).localname, canonical(prop)))
    else:
        raise ValueError("current archive is not a direct unsigned property")
    for obj in signature.findall(f"{{{DS}}}Object"):
        if obj.find(f"{{{XA}}}QualifyingProperties") is None:
            parts.append(("other-Object", canonical(obj)))
    return parts

def proof_checks(tree, root):
    signature, info, value, cert = signer_material(tree)
    trusted_certificate(cert, root)
    reference_bytes(tree, info)
    props = unsigned(signature)
    if props is None:
        return []
    proofs, previous = [], None
    for prop in props:
        tag = etree.QName(prop)
        if (tag.namespace, tag.localname) not in {(XA, "SignatureTimeStamp"), (X4, "ArchiveTimeStamp")}:
            continue
        method = prop.find(f"{{{DS}}}CanonicalizationMethod")
        if method is None or method.get("Algorithm") != EXC:
            raise ValueError("timestamp canonicalization")
        token = decode(prop.find(f"{{{XA}}}EncapsulatedTimeStamp").text)
        imprint, tsa, tst, nonce, policy = token_math(token, root)
        parts = [("SignatureValue", canonical(value))] if tag.localname == "SignatureTimeStamp" else archive_parts(tree, signature, info, value, prop)
        data = b"".join(data for _, data in parts)
        if hashlib.sha256(data).digest() != imprint:
            raise ValueError(f"{tag.localname} actual canonical coverage imprint mismatch")
        if tag.localname == "ArchiveTimeStamp" and not proofs:
            raise ValueError("archive without admitted signature-time proof")
        # Probe timestamps share one explicit fixed genTime; no SigningTime trust.
        previous = NOW if previous is None else max(previous, NOW)
        proofs.append((tag.localname, imprint, tsa, tst, nonce, policy, parts, token))
    return proofs

def status_checks(tree, root, responder):
    signature, _, _, document = signer_material(tree)
    trusted_certificate(responder, root, ExtendedKeyUsageOID.OCSP_SIGNING)
    proofs = proof_checks(tree, root)
    tsa_certificates = {proof[2].serial_number: proof[2] for proof in proofs}
    checked = 0
    for element in signature.xpath(".//x:EncapsulatedOCSPValue", namespaces=NS):
        response = ocsp.load_der_ocsp_response(decode(element.text))
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("unsuccessful OCSP response")
        responder.public_key().verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), response.signature_hash_algorithm)
        if any(etree.QName(n).localname == "TimeStampValidationData" for n in element.iterancestors()):
            target = tsa_certificates.get(response.serial_number)
            if target is None:
                raise ValueError("TSVD contains non-TSA status role")
        else:
            target = document
        request = ocsp.OCSPRequestBuilder().add_certificate(target, root, response.hash_algorithm).build()
        if response.serial_number != target.serial_number or response.issuer_name_hash != request.issuer_name_hash or response.issuer_key_hash != request.issuer_key_hash:
            raise ValueError("OCSP CertID not bound to actual issuer/role")
        if response.certificate_status != ocsp.OCSPCertStatus.GOOD or response.this_update_utc > NOW:
            raise ValueError("OCSP status/time")
        if response.next_update_utc is not None and response.next_update_utc < NOW:
            raise ValueError("stale current OCSP status")
        checked += 1
    return checked

def expected_failure(name, function, lines):
    try:
        function()
    except (ValueError, AssertionError, InvalidSignature) as error:
        lines.append(f"negative={name} rejected=true cause={type(error).__name__}:{error}")
        return
    raise AssertionError(f"independent negative accepted: {name}")

def run(out: Path):
    root = x509.load_der_x509_certificate(bounded(out / "trusted-root.der"))
    responder = x509.load_der_x509_certificate(bounded(out / "ocsp-certificate.der"))
    root.public_key().verify(root.signature, root.tbs_certificate_bytes, padding.PKCS1v15(), root.signature_hash_algorithm)
    lines = [f"python={platform.python_version()}", f"libxml2={etree.LIBXML_VERSION}", f"cryptography={cryptography.__version__}", f"bounded_input_limit={LIMIT}", "standard=EN319132-1 V1.2.1 sections5.3/5.5.2.2 non-distributed v1.4.1", "production_SDK_imports=none", "TSA_RSA_math=independent cryptography; trust=explicit synthetic direct-root subset"]
    files = ["bounded-B.xml", "bounded-T.xml", "bounded-LT.xml", "bounded-LTA.xml", "bounded-renewed-LTA.xml", "bounded-extra-object-LTA.xml"]
    for file in files:
        tree = parse(out / file)
        proofs = proof_checks(tree, root)
        statuses = status_checks(tree, root, responder)
        lines.append(f"positive={file} rsa_math=true references=true all_present_proofs={len(proofs)} issuer_bound_current_status_values={statuses}")
    tree = parse(out / "bounded-LTA.xml")
    signature, info, value, _ = signer_material(tree)
    props = unsigned(signature)
    descriptor = signature.find(f"{{{DS}}}Object/{{{XA}}}QualifyingProperties/{{{XA}}}SignedProperties/{{{XA}}}SignedDataObjectProperties/{{{XA}}}DataObjectFormat")
    original_reference = descriptor.get("ObjectReference")
    for bad in ["#payload", "#foreign", "#sig-SignedProperties", "https://example.test/#payload"]:
        descriptor.set("ObjectReference", bad)
        expected_failure(f"baseline-reference-binding:{bad}", lambda: baseline_bindings(signature, info), lines)
    descriptor.set("ObjectReference", original_reference)
    mime = descriptor.find(f"{{{XA}}}MimeType")
    original_mime = mime.text
    mime.text = " "
    expected_failure("baseline-empty-MimeType", lambda: baseline_bindings(signature, info), lines)
    mime.text = original_mime
    descriptors = descriptor.getparent()
    duplicate = copy.deepcopy(descriptor)
    descriptors.append(duplicate)
    expected_failure("baseline-duplicate-descriptor", lambda: baseline_bindings(signature, info), lines)
    descriptors.remove(duplicate)
    current = props.find(f"{{{X4}}}ArchiveTimeStamp")
    parts = archive_parts(tree, signature, info, value, current)
    names = ["reference-payload", "reference-properties", "SignedInfo", "SignatureValue", "KeyInfo", "SignatureTimeStamp", "TimeStampValidationData", "RevocationValues"]
    if len(parts) != len(names):
        raise ValueError("canonical artifact topology changed")
    for name, (_, data) in zip(names, parts):
        if bounded(out / f"sdk-{name}.c14n") != data:
            raise AssertionError(f"exact independent canonical bytes differ: {name}")
        lines.append(f"canonical={name} exact=true sha256={hashlib.sha256(data).hexdigest()}")
    stream = b"".join(data for _, data in parts)
    if bounded(out / "sdk-archive-input.bin") != stream:
        raise AssertionError("exact complete archive octets differ")
    imprint = proof_checks(tree, root)[-1][1]
    wrong = parts.copy()
    wrong[2], wrong[3] = wrong[3], wrong[2]
    assert hashlib.sha256(b"".join(data for _, data in wrong)).digest() != imprint
    assert hashlib.sha256(b"".join(data for name, data in parts if name != "RevocationValues")).digest() != imprint
    lines += ["negative=archive-order-swap rejected=true", "negative=archive-status-omission rejected=true"]
    mutated = copy.deepcopy(tree)
    payload = mutated.xpath("//*[@Id='payload']")[0]
    payload.text = "FORGED" + (payload.text or "")
    expected_failure("actual-reference-content", lambda: proof_checks(mutated, root), lines)
    mutated = copy.deepcopy(tree)
    method = mutated.xpath("//ds:SignedInfo/ds:CanonicalizationMethod", namespaces=NS)[0]
    method.set("Algorithm", EXC + "WithComments")
    expected_failure("actual-signed-info", lambda: signer_material(mutated), lines)
    mutated = copy.deepcopy(tree)
    node = mutated.xpath("//ds:SignatureValue", namespaces=NS)[0]
    raw = bytearray(decode(node.text)); raw[0] ^= 1; node.text = base64.b64encode(raw).decode()
    expected_failure("actual-signature-value", lambda: signer_material(mutated), lines)
    mutated = copy.deepcopy(tree)
    ts = mutated.xpath("//x:SignatureTimeStamp/x:EncapsulatedTimeStamp", namespaces=NS)[0]
    ts.text = mutated.xpath("//a:ArchiveTimeStamp/x:EncapsulatedTimeStamp", namespaces=NS)[0].text
    expected_failure("genuine-token-wrong-binding", lambda: proof_checks(mutated, root), lines)
    mutated = copy.deepcopy(tree)
    node = mutated.xpath("//a:TimeStampValidationData", namespaces=NS)[0]
    node.set("URI", "#altered-protected-association")
    signer_material(mutated); reference_bytes(mutated, mutated.xpath("//ds:SignedInfo", namespaces=NS)[0])
    expected_failure("actual-protected-unsigned-property", lambda: proof_checks(mutated, root), lines)
    mutated = copy.deepcopy(tree)
    values = mutated.xpath("//x:EncapsulatedOCSPValue", namespaces=NS)
    tsa_value = next(n for n in values if any(etree.QName(p).localname == "TimeStampValidationData" for p in n.iterancestors()))
    document_value = next(n for n in values if not any(etree.QName(p).localname == "TimeStampValidationData" for p in n.iterancestors()))
    tsa_value.text = document_value.text
    # Check role before archive imprint: this is genuine signed issuer-bound
    # status for the WRONG leaf, not merely malformed/changed octets.
    response = ocsp.load_der_ocsp_response(decode(tsa_value.text))
    tsa_serials = {p[2].serial_number for p in proof_checks(tree, root)}
    assert response.serial_number not in tsa_serials
    lines.append("negative=current-TSA-wrong-status-role rejected=true genuine_OCSP_RSA_math_retained=true")
    renewed = parse(out / "bounded-renewed-LTA.xml")
    renewed.xpath("//a:TimeStampValidationData", namespaces=NS)[0].set("URI", "#changed-old-TSVD")
    expected_failure("renewed-archive-protects-old-TSVD", lambda: proof_checks(renewed, root), lines)
    extra = parse(out / "bounded-extra-object-LTA.xml")
    extra.xpath("//ds:Object[@Id='attachment']/*", namespaces=NS)[0].text = "changed extra Object"
    expected_failure("archive-other-Object", lambda: proof_checks(extra, root), lines)
    # Correlate every independently verified token to the actual loopback RFC3161
    # request and nonce. The signature keys are never read by this oracle.
    replies = {}
    for path in out.glob("pki-*-tsa-response.der"):
        response = sequence(bounded(path))
        request = sequence(bounded(path.with_name(path.name.replace("response", "request"))))
        request_nonce = next(integer(n) for n in request[2:] if n[0] == 2)
        replies[response[1][2]] = request_nonce
    tokens = 0
    for file in files:
        for proof in proof_checks(parse(out / file), root):
            if replies.get(proof[7]) != proof[4]:
                raise ValueError("actual issued nonce/request association")
            tokens += 1
    lines += [f"actual_RFC3161_request_nonce_matches={tokens}", "gost_document_math_oracle=not-run (SDK medium GOST backend independently recorded; no external GOST claim)", "oracle_topology=bounded generated ID+Exclusive profile/direct-root RSA; not arbitrary distributed-XAdES or production PKIX certification", "large_DOM=not-used; 1GiB_RSS_gate=not-run", "result=PASS"]
    text = "\n".join(lines) + "\n"
    (out / "X04-independent-oracle.txt").write_text(text, encoding="utf-8")
    print(text, end="")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args().out)
