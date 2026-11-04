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

RSA = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256,
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": hashes.SHA1,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512,
}

def verify_one(root, sig):
    signed_info = sig.find(q("SignedInfo"))
    result = {"signature_valid": False, "references": [], "supported": True}
    method = signed_info.find(q("SignatureMethod")).get("Algorithm")
    result["algorithm"] = method
    c14n = canon(signed_info, signed_info.find(q("CanonicalizationMethod")).get("Algorithm"))
    value = base64.b64decode("".join(sig.find(q("SignatureValue")).text.split()))
    holder = sig.find(".//" + q("X509Certificate"))
    if holder is None:
        # WS-Security: the signer certificate is the BinarySecurityToken / KeyIdentifier value.
        holder = next(e for e in root.iter()
                      if isinstance(e.tag, str) and etree.QName(e).localname in ("BinarySecurityToken", "KeyIdentifier") and e.text and e.text.strip())
    cert = x509.load_der_x509_certificate(base64.b64decode("".join(holder.text.split())))
    if method in RSA:
        try:
            cert.public_key().verify(value, c14n, padding.PKCS1v15(), RSA[method]())
            result["signature_valid"] = True
        except Exception as error:  # noqa: BLE001 - oracle reports, never raises
            result["error"] = str(error)
    else:
        # GOST (or any non-RSA) signature math has no independent verifier here.
        result["supported"] = False
    for ref in signed_info.findall(q("Reference")):
        uri = ref.get("URI", "")
        if uri == "":
            target = copy.deepcopy(root)
        else:
            found = [e for e in root.iter() if isinstance(e.tag, str) and any(etree.QName(k).localname in ("Id", "ID") and v == uri[1:] for k, v in e.attrib.items())]
            if not found:
                result["references"].append({"uri": uri, "match": False, "error": "target missing"})
                continue
            target = copy.deepcopy(found[0])
        algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        for transform in ref.findall(".//" + q("Transform")):
            a = transform.get("Algorithm")
            if a.endswith("enveloped-signature"):
                for s in target.findall(".//" + q("Signature")):
                    s.getparent().remove(s)
            elif "c14n" in a:
                algorithm = a
        digest_method = ref.find(q("DigestMethod")).get("Algorithm")
        if digest_method not in HASHES:
            result["references"].append({"uri": uri, "match": None, "unsupported_digest": digest_method})
            continue
        digest = HASHES[digest_method](canon(target, algorithm)).digest()
        expected = base64.b64decode("".join(ref.find(q("DigestValue")).text.split()))
        result["references"].append({"uri": uri, "match": digest == expected})
    result["subject"] = cert.subject.rfc4514_string()
    return result

def main(path):
    root = etree.parse(path).getroot()
    signatures = root.findall(".//" + q("Signature"))
    out = {"signatures": [verify_one(root, sig) for sig in signatures]}
    # An oracle that checked nothing must not look like a pass.
    out["checked"] = len(signatures) > 0 and all(len(s["references"]) > 0 for s in out["signatures"])
    print(json.dumps(out))

main(sys.argv[1])
