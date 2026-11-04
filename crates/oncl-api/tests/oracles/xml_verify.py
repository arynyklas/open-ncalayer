"""Independent XMLDSig oracle: lxml canonicalization + cryptography RSA verify.
Usage: xml_verify.py <signed.xml>; prints one JSON object."""
import base64, copy, hashlib, json, sys
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

DS = "http://www.w3.org/2000/09/xmldsig#"
q = lambda n: "{%s}%s" % (DS, n)
HASHES = {
    "http://www.w3.org/2001/04/xmlenc#sha256": hashlib.sha256,
    "http://www.w3.org/2000/09/xmldsig#sha1": hashlib.sha1,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashlib.sha512,
}

def canon(element, algorithm):
    exclusive = "exc-c14n" in algorithm
    return etree.tostring(element, method="c14n", exclusive=exclusive, with_comments="#WithComments" in algorithm)

def main(path):
    tree = etree.parse(path)
    root = tree.getroot()
    sig = root.find(".//" + q("Signature"))
    signed_info = sig.find(q("SignedInfo"))
    c14n = canon(signed_info, signed_info.find(q("CanonicalizationMethod")).get("Algorithm"))
    value = base64.b64decode("".join(sig.find(q("SignatureValue")).text.split()))
    cert = x509.load_der_x509_certificate(
        base64.b64decode("".join(sig.find(".//" + q("X509Certificate")).text.split())))
    result = {"signature_valid": False, "references": []}
    try:
        cert.public_key().verify(value, c14n, padding.PKCS1v15(), hashes.SHA256())
        result["signature_valid"] = True
    except Exception as error:  # noqa: BLE001 - oracle reports, never raises
        result["error"] = str(error)
    for ref in signed_info.findall(q("Reference")):
        uri = ref.get("URI", "")
        if uri == "":
            target = copy.deepcopy(root)
        else:
            found = [e for e in root.iter() if e.get("Id") == uri[1:] or e.get("ID") == uri[1:]]
            target = copy.deepcopy(found[0])
        algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        for transform in ref.findall(".//" + q("Transform")):
            a = transform.get("Algorithm")
            if a.endswith("enveloped-signature"):
                for s in target.findall(".//" + q("Signature")):
                    s.getparent().remove(s)
            elif "c14n" in a:
                algorithm = a
        digest = HASHES[ref.find(q("DigestMethod")).get("Algorithm")](canon(target, algorithm)).digest()
        expected = base64.b64decode("".join(ref.find(q("DigestValue")).text.split()))
        result["references"].append({"uri": uri, "match": digest == expected})
    result["subject"] = cert.subject.rfc4514_string()
    print(json.dumps(result))

main(sys.argv[1])
