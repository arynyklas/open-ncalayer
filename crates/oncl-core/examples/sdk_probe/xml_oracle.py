"""Independent bounded libxml2 C14N/digest and cryptography RSA oracle for X03.

Run after sdk_probe --case X03 --out DIR. Never parse the large source artifacts.
Dependencies: lxml and cryptography; neither is an SDK/runtime dependency.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
from pathlib import Path
from urllib.parse import unquote_to_bytes

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

LIMIT = 1_048_576
DS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"ds": DS}
METHODS = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
}


def bounded(path: Path) -> bytes:
    if path.stat().st_size > LIMIT:
        raise ValueError(f"independent oracle refuses unbounded input: {path}")
    with path.open("rb") as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(f"oracle input changed past its bound: {path}")
    return data


def parse(path: Path):
    tree = etree.parse(
        io.BytesIO(bounded(path)),
        etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False),
    )
    if tree.docinfo.doctype:
        raise ValueError("oracle fixtures must not contain a DTD")
    return tree


def decode(text: str) -> bytes:
    return base64.b64decode("".join(text.split()), validate=True)


def run(out: Path) -> None:
    lines = [
        f"oracle=independent-libxml2 version={etree.LIBXML_VERSION}",
        f"rsa_oracle=cryptography version={cryptography.__version__}",
        f"bounded_input_limit={LIMIT}",
    ]
    tree = parse(out / "oracle-input.xml")
    for name, exclusive, comments in [
        ("inclusive", False, False),
        ("inclusive-comments", False, True),
        ("exclusive", True, False),
        ("exclusive-comments", True, True),
    ]:
        expected = etree.tostring(
            tree, method="c14n", exclusive=exclusive, with_comments=comments
        )
        actual = bounded(out / f"oracle-{name}.xml")
        if actual != expected:
            raise AssertionError(f"exact independent canonical bytes differ: {name}")
        lines.append(
            f"canonical={name} exact=true sha256={hashlib.sha256(expected).hexdigest()}"
        )

    for file, expected_digest_match in [
        ("bounded-two-signers.xml", True),
        ("oracle-covered-mutated.xml", False),
        ("oracle-uncovered-mutated.xml", True),
    ]:
        tree = parse(out / file)
        checked = 0
        for signature in tree.xpath("//ds:Signature", namespaces=NS):
            info = signature.find(f"{{{DS}}}SignedInfo")
            method = info.find(f"{{{DS}}}SignatureMethod").get("Algorithm")
            if method != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                continue
            canonical_method = info.find(f"{{{DS}}}CanonicalizationMethod").get(
                "Algorithm"
            )
            exclusive, comments = METHODS[canonical_method]
            signed_info = etree.tostring(
                info,
                method="c14n",
                exclusive=exclusive,
                with_comments=comments,
                with_tail=False,
            )
            certificate = signature.find(
                f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate"
            )
            public = x509.load_der_x509_certificate(
                decode("".join(certificate.itertext()))
            ).public_key()
            value = signature.find(f"{{{DS}}}SignatureValue")
            public.verify(
                decode("".join(value.itertext())),
                signed_info,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            references = info.findall(f"{{{DS}}}Reference")
            if not references:
                raise AssertionError("RSA fixture has no actual references")
            for reference in references:
                uri = reference.get("URI")
                if not uri.startswith("#"):
                    raise AssertionError("bounded oracle fixture expects an ID reference")
                identity = unquote_to_bytes(uri[1:]).decode("utf-8", errors="strict")
                targets = tree.xpath("//*[@Id=$id]", id=identity)
                if len(targets) != 1:
                    raise AssertionError("reference identity is missing or ambiguous")
                methods = reference.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform")
                if len(methods) != 1:
                    raise AssertionError("oracle fixture changed its transform shape")
                exclusive, _ = METHODS[methods[0].get("Algorithm")]
                canonical = etree.tostring(
                    targets[0],
                    method="c14n",
                    exclusive=exclusive,
                    with_comments=False,  # short same-document ID dereferencing
                    with_tail=False,
                )
                algorithm = reference.find(f"{{{DS}}}DigestMethod").get("Algorithm")
                if algorithm != "http://www.w3.org/2001/04/xmlenc#sha256":
                    raise AssertionError("unexpected RSA reference digest algorithm")
                digest = hashlib.sha256(canonical).digest()
                expected = decode(reference.find(f"{{{DS}}}DigestValue").text)
                matches = digest == expected
                if matches != expected_digest_match:
                    raise AssertionError(f"independent mutation control failed: {file}")
                lines.append(
                    f"file={file} uri={uri} rsa_math=true reference_digest_matches={matches} "
                    f"reference_sha256={digest.hex()} signed_info_sha256={hashlib.sha256(signed_info).hexdigest()}"
                )
            checked += 1
        if checked == 0:
            raise AssertionError(f"no independently verified RSA signer: {file}")
    lines.append("gost_oracle=not-run; no cryptography/libxml2 GOST verification claim")
    lines.append("result=PASS; no host trust verdict is inferred from RSA math")
    report = "\n".join(lines) + "\n"
    (out / "X03-independent-oracle.txt").write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args().out)
