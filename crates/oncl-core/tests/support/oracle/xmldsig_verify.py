#!/usr/bin/env python3
"""Independent XML-DSig oracle for the manual-window port tests.

Usage: xmldsig_verify.py <signed.xml> <signer-cert.der>

Verifies every ds:Signature of the document with lxml (canonicalisation) and
`cryptography` (digests, RSA PKCS#1 v1.5), nothing of OpenNCALayer: each Reference's
digest over the referenced node after its transforms, then SignedInfo's signature with the
public key of the given certificate. RSA signatures only (rsa-sha256, rsa-sha1); a GOST
signature is reported as `unsupported` and fails: GOST keys are checked by the repository's
own verifier (`oncl_xml::verify`) in the tests, not by this oracle.

Prints one JSON object: {"signatures": [{"valid": bool, "problems": [...], "references":
[{"uri": ..., "transforms": [...], "digest_method": ..., "digest_ok": bool, "node": local
name of the referenced element}], "signature_method": ..., "c14n": ..., "key_info_cert_ok":
bool|null}]}. Exit status 0 when every signature is valid and there is at least one, else 1.
"""
import base64
import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"ds": DS}
C14N = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
}
DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": hashlib.sha1,
    "http://www.w3.org/2001/04/xmlenc#sha256": hashlib.sha256,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashlib.sha512,
}
RSA_SIGNATURES = {
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": hashes.SHA1,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256,
}
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def canonicalize(node, uri):
    exclusive, comments = C14N[uri]
    return etree.tostring(
        node, method="c14n", exclusive=exclusive, with_comments=comments, with_tail=False
    )


def find_by_id(root, ident):
    """The ONE element with this Id; none or several (signature wrapping) is None."""
    found = []
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        if any(el.get(name) == ident for name in ("Id", "ID", "id")):
            found.append(el)
    return found[0] if len(found) == 1 else None


def verify_signature(xml_bytes, index, public_key, cert):
    """Verifies the `index`-th ds:Signature of a fresh parse of the document."""
    root = etree.fromstring(xml_bytes)
    signature = list(root.iter("{%s}Signature" % DS))[index]
    result = {"valid": False, "problems": [], "references": []}
    signed_info = signature.find("ds:SignedInfo", NS)
    c14n_method = signed_info.find("ds:CanonicalizationMethod", NS).get("Algorithm")
    sig_method = signed_info.find("ds:SignatureMethod", NS).get("Algorithm")
    result["c14n"] = c14n_method
    result["signature_method"] = sig_method
    if c14n_method not in C14N:
        result["problems"].append("unsupported c14n " + c14n_method)
        return result
    if sig_method not in RSA_SIGNATURES:
        result["problems"].append("unsupported signature method (unsupported): " + sig_method)
        return result
    all_ok = True
    if not signed_info.findall("ds:Reference", NS):
        result["problems"].append("no references")
        all_ok = False
    for ref in signed_info.findall("ds:Reference", NS):
        uri = ref.get("URI", "")
        entry = {"uri": uri, "transforms": [], "digest_ok": False, "node": None}
        result["references"].append(entry)
        # A fresh tree per reference: the enveloped transform edits it.
        tree = etree.fromstring(xml_bytes)
        sig = list(tree.iter("{%s}Signature" % DS))[index]
        if uri == "":
            node = tree
        elif uri.startswith("#"):
            node = find_by_id(tree, uri[1:])
        else:
            node = None
        if node is None:
            result["problems"].append("unresolvable or ambiguous reference " + uri)
            all_ok = False
            continue
        entry["node"] = etree.QName(node).localname
        c14n_uri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        for t in ref.findall("ds:Transforms/ds:Transform", NS):
            alg = t.get("Algorithm")
            entry["transforms"].append(alg)
            if alg == ENVELOPED:
                parent = sig.getparent()
                tail = sig.tail
                prev = sig.getprevious()
                parent.remove(sig)
                # lxml hands the removed element's tail text to nobody: keep the text.
                if tail:
                    if prev is not None:
                        prev.tail = (prev.tail or "") + tail
                    else:
                        parent.text = (parent.text or "") + tail
            elif alg in C14N:
                c14n_uri = alg
            else:
                result["problems"].append("unsupported transform " + alg)
                all_ok = False
        data = canonicalize(node, c14n_uri)
        method = ref.find("ds:DigestMethod", NS).get("Algorithm")
        entry["digest_method"] = method
        if method not in DIGESTS:
            result["problems"].append("unsupported digest " + method)
            all_ok = False
            continue
        expected = base64.b64decode("".join(ref.find("ds:DigestValue", NS).text.split()))
        entry["digest_ok"] = DIGESTS[method](data).digest() == expected
        if not entry["digest_ok"]:
            result["problems"].append("digest mismatch for " + uri)
            all_ok = False
    value = base64.b64decode("".join(signature.find("ds:SignatureValue", NS).text.split()))
    signed = canonicalize(signed_info, c14n_method)
    try:
        public_key.verify(value, signed, padding.PKCS1v15(), RSA_SIGNATURES[sig_method]())
        sig_ok = True
    except Exception as e:  # noqa: BLE001 - reported, not raised
        sig_ok = False
        result["problems"].append("SignatureValue does not verify: %r" % (e,))
    # The certificate the signature names, if any, is the signer's.
    certs = signature.findall("ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
    if certs:
        der = base64.b64decode("".join(certs[0].text.split()))
        result["key_info_cert_ok"] = der == cert.public_bytes(Encoding.DER)
    else:
        result["key_info_cert_ok"] = None
    result["valid"] = sig_ok and all_ok and result["key_info_cert_ok"] is not False
    return result


def main():
    xml_bytes = open(sys.argv[1], "rb").read()
    cert = x509.load_der_x509_certificate(open(sys.argv[2], "rb").read())
    public_key = cert.public_key()
    count = len(list(etree.fromstring(xml_bytes).iter("{%s}Signature" % DS)))
    if not isinstance(public_key, rsa.RSAPublicKey):
        print(json.dumps({"signatures": [], "error": "the oracle verifies RSA keys only"}))
        return 1
    signatures = [verify_signature(xml_bytes, i, public_key, cert) for i in range(count)]
    print(json.dumps({"signatures": signatures}))
    return 0 if signatures and all(s["valid"] for s in signatures) else 1


if __name__ == "__main__":
    sys.exit(main())
