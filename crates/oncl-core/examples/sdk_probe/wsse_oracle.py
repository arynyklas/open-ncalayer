#!/usr/bin/env python3
"""Independent bounded WSSE oracle: libxml2 C14N + cryptography RSA math.

No production SDK imports. Every input <= 1 MiB BEFORE parsing; no large DOM.
Tests the actual pinned NCANode external RSA fixture as math-only (expired CA),
and probe-created direct-root RSA fixtures with explicit fixed synthetic as-of.
GOST inputs: canonical decomposition only, not independent signature math/trust.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from lxml import etree
import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CAP = 1024 * 1024
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
DS = "http://www.w3.org/2000/09/xmldsig#"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
X509 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
B64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
RSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)

def insist(value, message):
    if not value:
        raise ValueError(message)

def children(node):
    return [child for child in node if isinstance(child.tag, str)]

def exactly(node, tag):
    found = [child for child in children(node) if child.tag == tag]
    insist(len(found) == 1, f"unique direct child {tag}")
    return found[0]

def canonical(node):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False)

def binary(node):
    insist(not children(node), "nested binary content")
    return base64.b64decode("".join("".join(node.itertext()).split()), validate=True)

def load(path):
    insist(path.stat().st_size <= CAP, "oracle input exceeds hard 1-MiB DOM cap")
    with path.open("rb") as stream:
        raw = stream.read(CAP + 1)
    insist(len(raw) <= CAP, "oracle input grew beyond hard DOM cap")
    insist(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(), "DTD/entity forbidden")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False, remove_blank_text=False)
    root = etree.fromstring(raw, parser)
    insist(not root.getroottree().docinfo.doctype, "DOCTYPE forbidden")
    return root

def verify(root, *, root_cert=None, rsa_math=True):
    insist(root.tag == f"{{{SOAP}}}Envelope", "actual SOAP 1.1 Envelope")
    parts = children(root)
    insist([part.tag for part in parts] == [f"{{{SOAP}}}Header", f"{{{SOAP}}}Body"], "Header then actual unique direct Body")
    header, body = parts
    insist(all(node is body or etree.QName(node).localname != "Body" for node in root.iter() if isinstance(node.tag, str)), "wrapped/duplicate Body")
    ids = {}
    for node in root.iter():
        if not isinstance(node.tag, str):
            continue
        aliases = [(key, value) for key, value in node.attrib.items() if key in [f"{{{WSU}}}Id", "Id", "ID", "id", "{http://www.w3.org/XML/1998/namespace}id"]]
        insist(len(aliases) <= 1, "ID aliases")
        for _, value in aliases:
            insist(value not in ids, "duplicate full Id")
            ids[value] = node
    body_id = body.get(f"{{{WSU}}}Id")
    insist(body_id and ids[body_id] is body, "exact used Body WSU Id")
    securities = [node for node in children(header) if node.tag == f"{{{WSSE}}}Security"]
    roles = [node.get(f"{{{SOAP}}}actor", "") for node in securities]
    insist(len(roles) == len(set(roles)), "duplicate recipient Security")
    selected = [node for node in securities if not node.get(f"{{{SOAP}}}actor")]
    insist(len(selected) == 1, "unique selected recipient")
    security = selected[0]
    signatures = [node for node in children(security) if node.tag == f"{{{DS}}}Signature"]
    insist(1 <= len(signatures) <= 16, "all selected signatures bounded")
    result = []
    for signature in signatures:
        info = exactly(signature, f"{{{DS}}}SignedInfo")
        insist(exactly(info, f"{{{DS}}}CanonicalizationMethod").get("Algorithm") == EXC, "exclusive SignedInfo")
        method = exactly(info, f"{{{DS}}}SignatureMethod").get("Algorithm")
        references = [node for node in children(info) if node.tag == f"{{{DS}}}Reference"]
        insist(len(references) == 1 and references[0].get("URI") == f"#{body_id}", "actual direct used Body reference, not whole-document/other-node math")
        reference = references[0]
        transforms = exactly(reference, f"{{{DS}}}Transforms")
        insist(len(children(transforms)) == 1 and exactly(transforms, f"{{{DS}}}Transform").get("Algorithm") == EXC, "complete Body transform")
        key = exactly(signature, f"{{{DS}}}KeyInfo")
        insist(len(children(key)) == 1, "unambiguous KeyInfo")
        token_reference = exactly(key, f"{{{WSSE}}}SecurityTokenReference")
        insist(len(children(token_reference)) == 1, "unambiguous STR")
        token = children(token_reference)[0]
        if token.tag == f"{{{WSSE}}}Reference":
            uri = token.get("URI", "")
            insist(uri.startswith("#") and "%" not in uri and uri[1:] in ids, "local bare-name STR")
            token = ids[uri[1:]]
            insist(token.getparent() is security and token.tag == f"{{{WSSE}}}BinarySecurityToken", "same-recipient token, not global/header fallback")
        else:
            insist(token.tag == f"{{{WSSE}}}KeyIdentifier", "supported pinned token form")
        insist(token.get("ValueType") == X509 and token.get("EncodingType") == B64, "actual X509v3 encoding/type")
        der = binary(token)
        cert = x509.load_der_x509_certificate(der)
        body_bytes, info_bytes = canonical(body), canonical(info)
        row = {"certificate_sha256": hashlib.sha256(der).hexdigest(), "body_c14n_sha256": hashlib.sha256(body_bytes).hexdigest(), "body_c14n_bytes": len(body_bytes), "signed_info_c14n_sha256": hashlib.sha256(info_bytes).hexdigest(), "signed_info_c14n_bytes": len(info_bytes), "algorithm": method}
        if rsa_math:
            insist(method == RSA256 and exactly(reference, f"{{{DS}}}DigestMethod").get("Algorithm") == SHA256, "oracle RSA-SHA256-only math")
            insist(binary(exactly(reference, f"{{{DS}}}DigestValue")) == hashlib.sha256(body_bytes).digest(), "covered Body digest mismatch")
            key = cert.public_key()
            insist(isinstance(key, rsa.RSAPublicKey), "RSA public key")
            key.verify(binary(exactly(signature, f"{{{DS}}}SignatureValue")), info_bytes, padding.PKCS1v15(), hashes.SHA256())
            row["signature_math"] = "passed-independent-cryptography"
            if root_cert:
                insist(cert.issuer == root_cert.subject, "direct synthetic issuer")
                root_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
                insist(cert.not_valid_before_utc <= NOW <= cert.not_valid_after_utc, "synthetic leaf validity at explicit as-of")
                insist(root_cert.not_valid_before_utc <= NOW <= root_cert.not_valid_after_utc, "synthetic root validity")
                row["certificate_scope"] = "direct-explicit-synthetic-root-and-validity; no independent OCSP/trust-store claim"
            else:
                row["certificate_scope"] = "math-only external historical fixture; expired certificate NOT promoted to Valid"
        else:
            row["signature_math"] = "NOT evaluated: independent GOST verifier not present"
        result.append((row, body_bytes, info_bytes))
    return result

def unbound_reference_math(root):
    """Show why valid reference/signature math alone does NOT prove used Body."""
    signature = root.find(f".//{{{DS}}}Signature")
    info = exactly(signature, f"{{{DS}}}SignedInfo")
    reference = exactly(info, f"{{{DS}}}Reference")
    identity = reference.get("URI")[1:]
    targets = [node for node in root.iter() if isinstance(node.tag, str) and node.get(f"{{{WSU}}}Id") == identity]
    insist(len(targets) == 1, "unique referenced old Body for math-only control")
    insist(hashlib.sha256(canonical(targets[0])).digest() == binary(exactly(reference, f"{{{DS}}}DigestValue")), "old Body digest changed")
    token = signature.find(f".//{{{WSSE}}}KeyIdentifier")
    key = x509.load_der_x509_certificate(binary(token)).public_key()
    key.verify(binary(exactly(signature, f"{{{DS}}}SignatureValue")), canonical(info), padding.PKCS1v15(), hashes.SHA256())

def negative(name, root, edit):
    changed = copy.deepcopy(root)
    edit(changed)
    try:
        verify(changed)
    except Exception:
        return name
    raise AssertionError(f"negative control accepted: {name}")

def main():
    directory = Path(sys.argv[1])
    root_cert = x509.load_der_x509_certificate((directory / "root.der").read_bytes())
    report = {"lxml": etree.LXML_VERSION, "libxml2": etree.LIBXML_VERSION, "cryptography": cryptography.__version__, "dom_cap_bytes": CAP, "as_of": NOW.isoformat(), "fixtures": {}, "negative_controls": []}
    for name, trust, math in [("bounded-rsa.xml", root_cert, True), ("pinned-ncanode.xml", None, True), ("bounded-gost04.xml", None, False), ("bounded-gost15-bst.xml", None, False)]:
        root = load(directory / name)
        results = verify(root, root_cert=trust, rsa_math=math)
        report["fixtures"][name] = [row for row, _, _ in results]
        for index, (_, body, info) in enumerate(results):
            (directory / f"{name}.{index}.body.c14n").write_bytes(body)
            (directory / f"{name}.{index}.signed-info.c14n").write_bytes(info)
    root = load(directory / "bounded-rsa.xml")
    def body(root):
        return root.find(f"{{{SOAP}}}Body")
    report["negative_controls"].append(negative("covered-body-mutation", root, lambda r: setattr(body(r).find(".//marker"), "text", "attacker")))
    def wrap(r):
        old = body(r)
        r.remove(old)
        wrapper = etree.SubElement(r.find(f"{{{SOAP}}}Header"), "{urn:attacker}wrapper")
        wrapper.append(old)
        etree.SubElement(r, f"{{{SOAP}}}Body").text = "unsigned replacement"
        unbound_reference_math(r)
        report["wrapped_old_body_math"] = "reference digest and RSA signature still valid; actual used-Body binding rejects"
    report["negative_controls"].append(negative("valid-old-body-math-wrapping", root, wrap))
    def duplicate(r):
        etree.SubElement(r.find(f"{{{SOAP}}}Header"), "{urn:attacker}duplicate", {f"{{{WSU}}}Id": body(r).get(f"{{{WSU}}}Id")})
    report["negative_controls"].append(negative("duplicate-wsu-id", root, duplicate))
    report["negative_controls"].append(negative("unsupported-signature-algorithm", root, lambda r: r.find(f".//{{{DS}}}SignatureMethod").set("Algorithm", "urn:attacker")))
    changed_info = copy.deepcopy(root)
    changed_info.find(f".//{{{DS}}}SignedInfo").set("Id", "changed-supported-signed-info")
    insist(canonical(body(changed_info)) == canonical(body(root)), "SignedInfo control changed Body")
    try:
        verify(changed_info)
    except InvalidSignature:
        report["negative_controls"].append("supported-signedinfo-change-fails-actual-rsa-math")
    else:
        raise AssertionError("supported SignedInfo mutation did not fail at RSA signature verification")
    report["negative_controls"].append(negative("wrong-token-valuetype", root, lambda r: r.find(f".//{{{WSSE}}}KeyIdentifier").set("ValueType", "urn:attacker")))
    report["negative_controls"].append(negative("wrong-header-recipient", root, lambda r: r.find(f".//{{{WSSE}}}Security").set(f"{{{SOAP}}}actor", "urn:other")))
    changed = copy.deepcopy(root)
    changed.find(f"{{{SOAP}}}Header")[0].text = "changed uncovered metadata"
    verify(changed, root_cert=root_cert)
    report["uncovered_header_control"] = "signature math passed, no attribution of application header"
    (directory / "independent-oracle.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
