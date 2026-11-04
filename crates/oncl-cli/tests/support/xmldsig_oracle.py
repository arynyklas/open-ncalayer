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


def main():
    signed, leaf = sys.argv[1], sys.argv[2]
    tree = etree.parse(signed)
    root = tree.getroot()
    signatures = list(root.iter(q("Signature")))
    if not signatures:
        sys.exit("no signature")
    signature = signatures[0]
    info = signature.find(q("SignedInfo"))
    method = info.find(q("SignatureMethod")).get("Algorithm")
    if method != RSA_SHA256:
        sys.exit("oracle covers RSA-SHA256 only: " + method)
    references = info.findall(q("Reference"))
    ids = {el.get("Id"): el for el in root.iter() if el.get("Id")}
    for reference in references:
        digest_method = reference.find(q("DigestMethod")).get("Algorithm")
        if digest_method != SHA256:
            sys.exit("oracle covers SHA-256 digests only: " + digest_method)
        uri = reference.get("URI")
        transforms = [
            t.get("Algorithm")
            for t in reference.findall("%s/%s" % (q("Transforms"), q("Transform")))
        ]
        if uri == "":
            work = copy.deepcopy(tree)
            target = work
        else:
            work = copy.deepcopy(tree)
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
        if uri != "" and not transforms:
            # No explicit canonicalization: same-document default is inclusive.
            pass
        expected = base64.b64decode(reference.find(q("DigestValue")).text)
        actual = hashlib.sha256(canonical(target, c14n_uri)).digest()
        if expected != actual:
            sys.exit("reference digest mismatch for %r" % uri)
    c14n_uri = info.find(q("CanonicalizationMethod")).get("Algorithm")
    # SignedInfo is canonicalized inside its signature document context.
    value = base64.b64decode(signature.find(q("SignatureValue")).text)
    public = x509.load_der_x509_certificate(open(leaf, "rb").read()).public_key()
    public.verify(value, canonical(info, c14n_uri), padding.PKCS1v15(), hashes.SHA256())
    print("OK %d %s" % (len(references), c14n_uri))


main()
