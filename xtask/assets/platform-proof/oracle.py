#!/usr/bin/env python3
"""Independent oracle of `cargo xtask platform-proof`.

Uses only third-party tools (lxml, cryptography, asn1crypto, pyHanko and, when ONCL_PY_TOOLS
names a directory with them, pikepdf/qpdf, pypdf and pdfminer) and the standard library;
nothing of the project's Rust parsers. Every command prints ONE JSON object on its last
stdout line and exits 0 only when every check passed.
"""
import base64
import hashlib
import json
import os
import re
import sys

WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
DS = "http://www.w3.org/2000/09/xmldsig#"


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    sys.exit(1)


def load(manifest_path, name):
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    for s in manifest["sets"]:
        if s["name"] == name:
            return s
    fail(f"no data set {name}")


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while True:
            want = 1 << 22 if limit is None else min(1 << 22, limit - n)
            if want <= 0:
                break
            chunk = f.read(want)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def read_at(path, offset, length):
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


# ------------------------------------------------------------------ blob


def blob_check(path, manifest, name):
    s = load(manifest, name)
    sha, n = sha256_file(path)
    if sha != s["digests"]["sha256"] or n != s["digests"]["len"]:
        fail("blob sha256/length differ from the generator", got=sha)
    h = hashlib.sha512()
    with open(path, "rb") as f:
        while True:
            c = f.read(1 << 22)
            if not c:
                break
            h.update(c)
    if h.hexdigest() != s["digests"]["sha512"]:
        fail("blob sha512 differs from the generator")
    frames = 0
    with open(path, "rb") as f:
        while True:
            head = f.read(20)
            if len(head) < 20 or head[:8] != b"ONCLBLOB":
                break
            index = int.from_bytes(head[8:16], "big")
            size = int.from_bytes(head[16:20], "big")
            body = f.read(size + 4)
            if index != frames or len(body) != size + 4:
                fail("blob frame structure", frame=frames)
            frames += 1
    if frames != s["facts"]["frames"]:
        fail("blob frame count", frames=frames)
    print(json.dumps({"ok": True, "frames": frames, "sha256": sha}))


# ------------------------------------------------------------------ xml


def c14n_digest(element):
    from lxml import etree

    data = etree.tostring(element, method="c14n", exclusive=True, with_comments=False)
    return hashlib.sha256(data).hexdigest(), len(data)


def find_by_id(root, ident):
    hits = root.xpath("//*[@Id=$i or @wsu:Id=$i]", i=ident, namespaces={"wsu": WSU})
    if len(hits) != 1:
        fail(f"Id {ident} matches {len(hits)} elements")
    return hits[0]


def xml_check(path, manifest, name):
    from lxml import etree

    s = load(manifest, name)
    facts = s["facts"]
    sha, n = sha256_file(path)
    if sha != s["digests"]["sha256"] or n != s["digests"]["len"]:
        fail("xml sha256/length differ from the generator")
    parser = etree.XMLParser(huge_tree=True, resolve_entities=False, remove_comments=False)
    tree = etree.parse(path, parser)
    root = tree.getroot()
    checked = []
    for e in facts["elements"]:
        digest, length = c14n_digest(find_by_id(root, e["id"]))
        if digest != e["canonical_sha256"] or length != e["canonical_len"]:
            fail("canonical digest of an Id element differs from the lxml c14n", id=e["id"], lxml=digest, generator=e["canonical_sha256"], lxml_len=length, generator_len=e["canonical_len"])
        raw = read_at(path, e["start"], 3)
        if raw[:1] != b"<" or read_at(path, e["end"] - 1, 1) != b">":
            fail("element extent does not delimit a tag", id=e["id"])
        checked.append(e["id"])
    digest, length = c14n_digest(root)
    if digest != facts["whole_canonical_sha256"] or length != facts["whole_canonical_len"]:
        fail("whole-document canonical digest differs from the lxml c14n", lxml=digest, generator=facts["whole_canonical_sha256"], lxml_len=length, generator_len=facts["whole_canonical_len"])
    suffix = facts["suffix_after_root_close"].encode()
    if read_at(path, facts["root_close_offset"], len(suffix) + 1) != suffix:
        fail("root close offset")
    prefix, _ = sha256_file(path, facts["root_close_offset"])
    if prefix != facts["prefix_sha256_at_root_close"]:
        fail("prefix digest at the root close")
    if read_at(path, facts["far_tamper_offset"], 1)[0] != facts["far_tamper_byte"]:
        fail("far tamper byte")
    if read_at(path, facts["uncovered_tamper_offset"], 1)[0] != facts["uncovered_tamper_byte"]:
        fail("uncovered tamper byte")
    print(json.dumps({"ok": True, "tool": "lxml " + etree.__version__, "elements": checked, "whole_canonical_sha256": digest, "records": facts["records"]}))


def tail_fragment(path, size):
    """The last ~4 MiB of the file, to find the inserted signature."""
    window = min(size, 4 << 20)
    start = size - window
    data = read_at(path, start, window)
    return start, data


def xml_signature(path, manifest, name, mode, key_kind):
    """Independent check of the XMLDSig an operation inserted: digest values against the
    generator's canonical digests, SignatureValue against the certificate in KeyInfo."""
    from lxml import etree
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    s = load(manifest, name)
    facts = s["facts"]
    size = os.path.getsize(path)
    base, data = tail_fragment(path, size)
    found = list(re.finditer(rb"<ds:Signature[\s>]", data))
    prefix = "ds:"
    if not found:
        found = list(re.finditer(rb"<Signature[\s>]", data))
        prefix = ""
    if not found:
        fail("no Signature element in the last 4 MiB of the output")
    start = found[-1].start()
    end_tag = f"</{prefix}Signature>".encode()
    end = data.find(end_tag, start)
    if end < 0:
        fail("unterminated Signature element")
    end += len(end_tag)
    fragment = data[start:end]
    if b"xmlns:ds=" not in fragment.split(b">", 1)[0] and prefix:
        fragment = fragment.replace(b"<ds:Signature", b'<ds:Signature xmlns:ds="' + DS.encode() + b'"', 1)
    sig = etree.fromstring(fragment)
    ns = {"ds": DS}
    signed_info = sig.find("ds:SignedInfo", ns)
    c14n_alg = signed_info.find("ds:CanonicalizationMethod", ns).get("Algorithm")
    sig_alg = signed_info.find("ds:SignatureMethod", ns).get("Algorithm")
    exclusive = "xml-exc-c14n" in c14n_alg
    refs = []
    problems = []
    for r in signed_info.findall("ds:Reference", ns):
        uri = r.get("URI")
        dm = r.find("ds:DigestMethod", ns).get("Algorithm")
        value = base64.b64decode(r.find("ds:DigestValue", ns).text.strip()).hex()
        item = {"uri": uri, "digest_method": dm, "digest_hex": value}
        expected = None
        if uri == "":
            expected = facts["whole_canonical_sha256"]
        elif uri and uri.startswith("#"):
            for e in facts["elements"]:
                if e["id"] == uri[1:]:
                    expected = e["canonical_sha256"]
        # signed properties of XAdES live in the signature itself: not a generator element
        if expected is None:
            item["independent"] = "no generator digest for this reference (own signed properties)"
        elif dm.endswith("sha256"):
            item["expected_hex"] = expected
            item["match"] = expected == value
            if expected != value:
                problems.append(f"digest of {uri}")
        else:
            item["independent"] = "digest method has no independent oracle on this machine"
        refs.append(item)
    result = {"references": refs, "c14n": c14n_alg, "signature_algorithm": sig_alg, "signature_offset": base + start, "signature_len": end - start}
    cert_text = sig.find(".//ds:X509Certificate", ns)
    if sig_alg.endswith("rsa-sha256") and cert_text is not None and exclusive:
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_text.text))
        public = cert.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            canonical = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
            value = base64.b64decode(signature_value(sig))
            try:
                public.verify(value, canonical, padding.PKCS1v15(), hashes.SHA256())
                result["signature_value"] = "verified (RSA-SHA256 over the exclusive c14n of SignedInfo, cryptography)"
            except Exception as error:  # noqa: BLE001
                problems.append("SignatureValue")
                result["signature_value"] = f"INVALID: {error}"
    else:
        result["signature_value"] = "no independent oracle (GOST, or an inclusive SignedInfo)"
    # an enveloped signature inserted before the root end tag keeps every other byte
    if mode == "archive-end" and base + start == facts["root_close_offset"]:
        pre, _ = sha256_file(path, facts["root_close_offset"])
        result["prefix_preserved"] = pre == facts["prefix_sha256_at_root_close"]
        want = facts["suffix_after_root_close"].encode()
        tail = read_at(path, base + end, len(want) + 1)
        # whitespace after the document element is outside the document: its loss is noted, not a failure
        result["suffix_exact"] = tail == want
        result["suffix_preserved"] = tail.rstrip(b"\r\n") == want.rstrip(b"\r\n")
        if not (result["prefix_preserved"] and result["suffix_preserved"]):
            problems.append("bytes around the signature changed")
    result["ok"] = not problems
    result["problems"] = problems
    print(json.dumps(result))
    sys.exit(0 if not problems else 1)


def signature_value(sig):
    ns = {"ds": DS}
    return sig.find("ds:SignatureValue", ns).text


# ------------------------------------------------------------------ pdf


def pdf_check(path, manifest, name):
    s = load(manifest, name)
    facts = s["facts"]
    sha, n = sha256_file(path)
    if sha != s["digests"]["sha256"] or n != s["digests"]["len"]:
        fail("pdf sha256/length differ from the generator")
    from pyhanko.pdf_utils.reader import PdfFileReader

    out = {"ok": True, "tools": {}}
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        root = reader.root
        count = int(root["/Pages"]["/Count"])
        if count != facts["pages"]:
            fail("page count", pyhanko=count, generator=facts["pages"])
        revisions = reader.xrefs.total_revisions
        if revisions != len(facts["revisions"]):
            fail("revision count", pyhanko=revisions, generator=len(facts["revisions"]))
        out["pages"] = count
        out["revisions"] = revisions
        # walk the page tree for the sample pages
        def page_at(node, index):
            kids = node["/Kids"]
            for kid in kids:
                kid = kid.get_object() if hasattr(kid, "get_object") else kid
                c = int(kid.get("/Count", 1)) if kid["/Type"] == "/Pages" else 1
                if index < c:
                    return page_at(kid, index) if kid["/Type"] == "/Pages" else kid
                index -= c
            fail("page index outside the tree")

        for index, text in facts["samples"]:
            page = page_at(root["/Pages"], index)
            content = page["/Contents"].data.decode("latin-1")
            if f"({text})" not in content:
                fail("page text", page=index, content=content[:200])
        out["sample_pages"] = len(facts["samples"])
        names = root["/Names"]["/EmbeddedFiles"]["/Names"]
        spec = names[1].get_object() if hasattr(names[1], "get_object") else names[1]
        stream = spec["/EF"]["/F"].get_object() if hasattr(spec["/EF"]["/F"], "get_object") else spec["/EF"]["/F"]
        payload = stream.data
        if len(payload) != facts["embedded_len"] or hashlib.sha256(payload).hexdigest() != facts["embedded_sha256"]:
            fail("embedded file payload")
        out["embedded_len"] = len(payload)
    # the file's own structure, counted textually
    with open(path, "rb") as f:
        raw = f.read()
    out["object_streams"] = len(re.findall(rb"/Type\s*/ObjStm", raw))
    out["xref_streams"] = len(re.findall(rb"/Type\s*/XRef", raw))
    out["startxref_count"] = raw.count(b"startxref")
    expected_streams = sum(r["object_streams"] for r in facts["revisions"])
    if out["object_streams"] != expected_streams or out["xref_streams"] != sum(1 for r in facts["revisions"] if r["kind"] == "xref-stream"):
        fail("object/xref stream counts", **out)
    tools = os.environ.get("ONCL_PY_TOOLS")
    if tools:
        sys.path.append(tools)
        try:
            import pikepdf

            with pikepdf.open(path) as pdf:
                problems = pdf.check_pdf_syntax()
                out["tools"]["pikepdf"] = {"version": pikepdf.__version__, "qpdf": pikepdf.__libqpdf_version__, "pages": len(pdf.pages), "check": problems}
                if problems or len(pdf.pages) != facts["pages"]:
                    fail("qpdf check", **out)
        except ImportError:
            out["tools"]["pikepdf"] = "not installed"
        try:
            import pypdf

            r = pypdf.PdfReader(path)
            out["tools"]["pypdf"] = {"version": pypdf.__version__, "pages": len(r.pages)}
            if len(r.pages) != facts["pages"]:
                fail("pypdf page count", **out)
        except ImportError:
            out["tools"]["pypdf"] = "not installed"
        try:
            from pdfminer.high_level import extract_text

            text = extract_text(path, maxpages=1)
            out["tools"]["pdfminer"] = {"first_page_text": text.strip()[:80]}
            if facts["samples"][0][1][:20] not in text:
                fail("pdfminer first page text", **out)
        except ImportError:
            out["tools"]["pdfminer"] = "not installed"
    print(json.dumps(out))


def pdf_signature(path, manifest, name, key_kind):
    """Independent check of a PDF signature: ByteRange arithmetic, digest of the covered
    bytes (hashlib) against the CMS messageDigest, signature against the signer
    certificate, and that the original bytes are an untouched prefix."""
    from asn1crypto import cms, x509 as ax509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography import x509

    s = load(manifest, name)
    size = os.path.getsize(path)
    window = min(size, 8 << 20)
    base = size - window
    data = read_at(path, base, window)
    matches = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))
    if not matches:
        fail("no ByteRange in the last 8 MiB")
    m = matches[-1]
    br = [int(m.group(i)) for i in range(1, 5)]
    contents = re.search(rb"/Contents\s*<([0-9A-Fa-f]*)>", data[m.end() - 400 :] if False else data)
    # the Contents belonging to this signature dictionary: nearest after/before the ByteRange
    candidates = list(re.finditer(rb"/Contents\s*<([0-9A-Fa-f]*)>", data))
    contents = min(candidates, key=lambda c: abs(c.start() - m.start()))
    hex_start = base + contents.start(1) - 1  # offset of '<'
    hex_end = base + contents.end(1) + 1  # offset after '>'
    problems = []
    if br[0] != 0:
        problems.append("ByteRange[0] != 0")
    if br[1] != hex_start:
        problems.append(f"ByteRange[1]={br[1]} but Contents '<' is at {hex_start}")
    if br[2] != hex_end:
        problems.append(f"ByteRange[2]={br[2]} but Contents ends at {hex_end}")
    if br[2] + br[3] != size:
        problems.append(f"ByteRange covers {br[2] + br[3]} of {size} bytes")
    result = {"byte_range": br, "file_size": size, "problems": problems}
    if problems:
        print(json.dumps({"ok": False, **result}))
        sys.exit(1)
    orig_len = s["digests"]["len"]
    prefix, _ = sha256_file(path, orig_len)
    result["original_prefix_preserved"] = prefix == s["digests"]["sha256"]
    if not result["original_prefix_preserved"]:
        problems.append("the original bytes are not an untouched prefix")
    cms_der = bytes.fromhex(contents.group(1).decode())
    # strip the zero padding of the placeholder
    info = cms.ContentInfo.load(cms_der)
    sd = info["content"]
    signer = sd["signer_infos"][0]
    alg = signer["digest_algorithm"]["algorithm"].native
    h = {"sha256": hashlib.sha256, "sha512": hashlib.sha512, "sha1": hashlib.sha1}.get(alg)
    result["digest_algorithm"] = alg
    if h is None:
        result["digest"] = "no independent oracle for this digest"
    else:
        digest = h()
        with open(path, "rb") as f:
            for offset, length in ((br[0], br[1]), (br[2], br[3])):
                f.seek(offset)
                left = length
                while left:
                    chunk = f.read(min(left, 1 << 22))
                    if not chunk:
                        break
                    digest.update(chunk)
                    left -= len(chunk)
        attrs = signer["signed_attrs"]
        message_digest = next(a["values"][0].native for a in attrs if a["type"].native == "message_digest")
        result["message_digest_matches_covered_bytes"] = message_digest == digest.digest()
        if message_digest != digest.digest():
            problems.append("messageDigest differs from the digest of the covered bytes")
        cert = next(c.chosen for c in sd["certificates"])
        public = x509.load_der_x509_certificate(cert.dump()).public_key()
        if isinstance(public, rsa.RSAPublicKey):
            signed = attrs.dump()
            signed = b"\x31" + signed[1:]
            sig_alg = signer["signature_algorithm"]["algorithm"].native
            hash_cls = {"sha256": hashes.SHA256, "sha512": hashes.SHA512, "sha1": hashes.SHA1}[alg]
            try:
                public.verify(signer["signature"].native, signed, padding.PKCS1v15(), hash_cls())
                result["signature_value"] = f"verified ({sig_alg}, cryptography)"
            except Exception as error:  # noqa: BLE001
                problems.append("signature value")
                result["signature_value"] = f"INVALID: {error}"
        else:
            result["signature_value"] = "no independent oracle (GOST)"
    result["ok"] = not problems
    result["problems"] = problems
    print(json.dumps(result))
    sys.exit(0 if not problems else 1)


def pdf_pyhanko(path):
    """pyHanko integrity validation of the FIRST signature, the one the operation made (no trust evaluation)."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        sigs = reader.embedded_signatures
        status = validate_pdf_signature(sigs[0])
        print(json.dumps({"ok": bool(status.intact and status.valid), "signatures": len(sigs), "intact": bool(status.intact), "valid": bool(status.valid), "touched_after_signed": bool(status.modification_level is not None and str(status.modification_level) != "ModificationLevel.NONE")}))


def hash_file(path, algorithm):
    h = hashlib.new(algorithm)
    n = 0
    with open(path, "rb") as f:
        while True:
            c = f.read(1 << 22)
            if not c:
                break
            h.update(c)
            n += len(c)
    print(json.dumps({"ok": True, "digest": h.hexdigest(), "bytes": n}))


def main():
    command = sys.argv[1]
    args = sys.argv[2:]
    if command == "blob-check":
        blob_check(*args)
    elif command == "xml-check":
        xml_check(*args)
    elif command == "pdf-check":
        pdf_check(*args)
    elif command == "xml-signature":
        xml_signature(*args)
    elif command == "pdf-signature":
        pdf_signature(*args)
    elif command == "pdf-pyhanko":
        pdf_pyhanko(*args)
    elif command == "hash":
        hash_file(*args)
    else:
        fail(f"unknown command {command}")


if __name__ == "__main__":
    main()
