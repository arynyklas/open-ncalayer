"""Independent bounded L01 XMLDSig oracle: libxml2 C14N and cryptography RSA.

No SDK import, trust verdict, GOST oracle or large-document/RSS claim. The
caller-selected public fixture XML is capped by the existing X04 oracle reader.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
from lxml import etree
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from xml_xades_oracle import bounded, parse, decode

DS = "http://www.w3.org/2000/09/xmldsig#"
ENV = DS + "enveloped-signature"
CANON = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
NS = {"ds": DS}

def canonical(node, method):
    if method not in (CANON, CANON + "#WithComments", EXC, EXC + "WithComments"):
        raise ValueError("unsupported independent canonicalization profile")
    # libxml2's subtree tostring API does not materialize inherited xml:*
    # attributes for the C14N 1.0 node-set boundary. Preserve the complete
    # namespace axis and nearest inherited XML attributes explicitly.
    if isinstance(node, etree._Element) and not method.startswith(EXC):
        prepared = etree.Element(node.tag, nsmap=node.nsmap)
        attributes = dict(node.attrib)
        inherited = {}
        for ancestor in node.iterancestors():
            for name, value in ancestor.attrib.items():
                if name.startswith("{http://www.w3.org/XML/1998/namespace}"):
                    inherited.setdefault(name, value)
        for name, value in inherited.items():
            attributes.setdefault(name, value)
        prepared.attrib.update(attributes)
        prepared.text = node.text
        prepared.extend(copy.deepcopy(child) for child in node)
        node = prepared
    return etree.tostring(node, method="c14n", exclusive=method.startswith(EXC),
                          with_comments=method.endswith("WithComments"), with_tail=False)

def remove_preserving_tail(node):
    parent, previous, tail = node.getparent(), node.getprevious(), node.tail or ""
    if previous is None:
        parent.text = (parent.text or "") + tail
    else:
        previous.tail = (previous.tail or "") + tail
    parent.remove(node)

def verify(tree):
    signatures = tree.xpath("//ds:Signature", namespaces=NS)
    if len(signatures) != 1:
        raise ValueError("oracle requires one actual signature per bounded fixture")
    signature = signatures[0]
    info = signature.find(f"{{{DS}}}SignedInfo")
    if info is None or info.find(f"{{{DS}}}SignatureMethod").get("Algorithm") != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
        raise ValueError("oracle covers RSA-SHA256, not GOST or another signature method")
    certificate = x509.load_der_x509_certificate(decode(signature.findtext(f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")))
    public = certificate.public_key()
    if not isinstance(public, rsa.RSAPublicKey):
        raise ValueError("RSA key required")
    references = info.findall(f"{{{DS}}}Reference")
    if not 1 <= len(references) <= 32:
        raise ValueError("reference count")
    for reference in references:
        uri = reference.get("URI")
        clone = copy.deepcopy(tree)
        active = clone.xpath("//ds:Signature", namespaces=NS)[0]
        if uri == "":
            target = clone
        elif uri and uri.startswith("#") and len(uri) <= 256:
            found = clone.xpath("//*[@Id=$id or @ID=$id or @xml:id=$id]", id=uri[1:])
            if len(found) != 1:
                raise ValueError("missing or duplicate target identity")
            target = found[0]
        else:
            raise ValueError("external/unsupported reference")
        method, empty = CANON, False
        transforms = reference.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform")
        for transform in transforms:
            algorithm = transform.get("Algorithm")
            if algorithm == ENV:
                if target is not clone and active in target.iterancestors():
                    empty = True
                elif target is clone or active in target.iterdescendants():
                    remove_preserving_tail(active)
            elif algorithm in (CANON, CANON + "#WithComments", EXC, EXC + "WithComments"):
                method = algorithm
            else:
                raise ValueError("unsupported reference transform")
        data = b"" if empty else canonical(target, method)
        digest = reference.find(f"{{{DS}}}DigestMethod").get("Algorithm")
        algorithms = {"http://www.w3.org/2001/04/xmlenc#sha256": hashlib.sha256,
                      "http://www.w3.org/2000/09/xmldsig#sha1": hashlib.sha1,
                      "http://www.w3.org/2001/04/xmlenc#sha512": hashlib.sha512}
        if digest not in algorithms or algorithms[digest](data).digest() != decode(reference.findtext(f"{{{DS}}}DigestValue")):
            raise ValueError("reference digest mismatch")
    method = info.find(f"{{{DS}}}CanonicalizationMethod").get("Algorithm")
    public.verify(decode(signature.findtext(f"{{{DS}}}SignatureValue")), canonical(info, method), padding.PKCS1v15(), hashes.SHA256())
    return len(references)

def run(out):
    manifest = json.loads(bounded(out / "plugin-xml-manifest.json"))
    lines = ["oracle=independent-libxml2-and-cryptography", "scope=bounded-RSA-XMLDSig-math-not-PKIX-or-GOST"]
    for name in manifest["rsa_files"]:
        if Path(name).name != name:
            raise ValueError("fixture name must be a basename")
        tree = parse(out / name)
        references = verify(tree)
        changed = copy.deepcopy(tree)
        targets = changed.xpath("//*[text()='actual WASM protected text']")
        if not targets:
            raise ValueError("substantive protected mutation control absent")
        targets[0].text = "independently altered protected text"
        try:
            verify(changed)
        except (ValueError, InvalidSignature):
            pass
        else:
            raise AssertionError("altered protected bytes were accepted")
        lines.append(f"file={name} references={references} rsa=verified protected-mutation=rejected")
    (out / "plugin-xml-oracle.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args().out)
