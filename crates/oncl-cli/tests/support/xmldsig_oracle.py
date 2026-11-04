"""Independent XML-DSig oracle: lxml canonicalization + `cryptography` RSA.

usage: xmldsig_oracle.py SIGNED.xml LEAF.der
Re-derives every Reference digest and the SignedInfo signature without any
oncl code. Exits 0 and prints `OK <references> <signedinfo-c14n-uri>`.
"""
import base64
import copy
import hashlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
C14N = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
}
ENVELOPED = DS + "enveloped-signature"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def q(name):
    return "{%s}%s" % (DS, name)


def canonical(node, uri):
    exclusive, comments = C14N[uri]
    return etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=comments)


def verify_signature(tree, signature, leaf, structural):
    info = signature.find(q("SignedInfo"))
    method = info.find(q("SignatureMethod")).get("Algorithm")
    references = info.findall(q("Reference"))
    if not references:
        sys.exit("SignedInfo has no Reference")
    value = base64.b64decode(signature.find(q("SignatureValue")).text)
    if not value:
        sys.exit("empty SignatureValue")
    if structural:
        # GOST algorithms: lxml/cryptography cannot compute GOST R 34.11/34.10, so the
        # math is NOT independently verified. Only the structure is checked.
        if "gost" not in method.lower():
            sys.exit("structural mode expects a GOST SignatureMethod: " + method)
        for reference in references:
            digest = base64.b64decode(reference.find(q("DigestValue")).text)
            if len(digest) not in (32, 64):
                sys.exit("unexpected GOST digest length %d" % len(digest))
        c14n_uri = info.find(q("CanonicalizationMethod")).get("Algorithm")
        if c14n_uri not in C14N:
            sys.exit("unknown SignedInfo canonicalization " + c14n_uri)
        return len(references), c14n_uri
    if method != RSA_SHA256:
        sys.exit("oracle covers RSA-SHA256 only: " + method)
    root = tree.getroot()
    for reference in references:
        digest_method = reference.find(q("DigestMethod")).get("Algorithm")
        if digest_method != SHA256:
            sys.exit("oracle covers SHA-256 digests only: " + digest_method)
        uri = reference.get("URI")
        transforms = [
            t.get("Algorithm")
            for t in reference.findall("%s/%s" % (q("Transforms"), q("Transform")))
        ]
        work = copy.deepcopy(tree)
        target = work
        if uri != "":
            target = None
            for el in work.getroot().iter():
                if el.get("Id") == uri[1:]:
                    target = el
                    break
            if target is None:
                sys.exit("unresolved reference " + uri)
        c14n_uri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        for transform in transforms:
            if transform == ENVELOPED:
                for sig in list(work.getroot().iter(q("Signature"))):
                    if sig.getparent() is not None:
                        sig.getparent().remove(sig)
            elif transform in C14N:
                c14n_uri = transform
            else:
                sys.exit("unsupported transform " + transform)
        expected = base64.b64decode(reference.find(q("DigestValue")).text)
        actual = hashlib.sha256(canonical(target, c14n_uri)).digest()
        if expected != actual:
            sys.exit("reference digest mismatch for %r" % uri)
    c14n_uri = info.find(q("CanonicalizationMethod")).get("Algorithm")
    public = x509.load_der_x509_certificate(open(leaf, "rb").read()).public_key()
    public.verify(value, canonical(info, c14n_uri), padding.PKCS1v15(), hashes.SHA256())
    return len(references), c14n_uri


def main():
    signed, leaf = sys.argv[1], sys.argv[2]
    structural = len(sys.argv) > 3 and sys.argv[3] == "gost"
    tree = etree.parse(signed)
    signatures = list(tree.getroot().iter(q("Signature")))
    if not signatures:
        sys.exit("no signature")
    total, first = 0, None
    for signature in signatures:  # every signature, not only the first
        refs, c14n_uri = verify_signature(tree, signature, leaf, structural)
        total += refs
        first = first or c14n_uri
    print("OK %d %s SIGNATURES=%d MODE=%s" % (total, first, len(signatures), "structural-gost" if structural else "rsa-math"))


main()
