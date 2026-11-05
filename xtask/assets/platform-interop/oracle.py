"""Independent oracles of `cargo xtask platform-interop`: asn1crypto / cryptography / lxml /
pyHanko, never any OpenNCALayer code. Every subcommand prints one JSON object; the caller
reads its fields, the exit status only says the script ran.

  cms-info FILE                      structure of a CMS (BER or DER)
  cms-verify FILE [--content FILE] [--root DER] [--at UNIX]
                                     RSA math of every RSA signer, message digests, timestamp
  cms-digest FILE --content FILE     messageDigest of the first signer vs a streebog/sha digest
  xmldsig-verify FILE [--cert DER]   every ds:Signature: reference digests (lxml canonical
                                     XML) and the RSA SignedInfo signature (cryptography)
  pdf-byterange FILE                 every signature of a PDF decomposed without a PDF library:
                                     ByteRange (regex over the raw bytes), the digest of the
                                     covered ranges (streamed), the CMS inside /Contents
                                     (messageDigest, RSA signature, timestamp token)
  pdf-verify FILE --root DER --at UNIX
                                     pyHanko: integrity, validity, trust under `root` at the
                                     given instant, DSS contents, document timestamps
  xades-info FILE                    XAdES structure: SigningCertificate digest, signature
                                     timestamp imprint (+ RSA TSA signature), evidence
"""
import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
import re
import sys

from asn1crypto import cms, core, keys, tsp, x509 as asn1_x509
from lxml import etree
from cryptography import x509 as c_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# asn1crypto has no spec for the public keys of GOST certificates: treat them as opaque.
_public_key_spec = keys.PublicKeyInfo._spec_callbacks["public_key"]


def _opaque_public_key_spec(self):
    try:
        return _public_key_spec(self)
    except KeyError:
        return (keys.OctetBitString, None)


keys.PublicKeyInfo._spec_callbacks = {"public_key": _opaque_public_key_spec}

DIGESTS = {
    "sha1": (hashlib.sha1, hashes.SHA1),
    "sha256": (hashlib.sha256, hashes.SHA256),
    "sha384": (hashlib.sha384, hashes.SHA384),
    "sha512": (hashlib.sha512, hashes.SHA512),
}

OID_SIGNING_TIME = "signing_time"
OID_TST = "signature_time_stamp_token"


def read(path):
    with open(path, "rb") as f:
        return f.read()


def out(obj):
    print(json.dumps(obj, sort_keys=True, default=str))
    sys.exit(0)


def load_signed_data(path):
    data = read(path)
    info = cms.ContentInfo.load(data)
    if info["content_type"].native != "signed_data":
        raise ValueError("not a CMS SignedData: " + info["content_type"].native)
    return data, info["content"]


def certs_of(sd):
    return [c.chosen for c in (sd["certificates"] or []) if c.name == "certificate"]


def find_cert(sd, sid):
    for cert in certs_of(sd):
        if sid.name == "issuer_and_serial_number":
            if (
                cert.serial_number == sid.chosen["serial_number"].native
                and cert.issuer == sid.chosen["issuer"]
            ):
                return cert
        elif sid.name == "subject_key_identifier":
            if cert.key_identifier == sid.chosen.native:
                return cert
    return None


def key_alg(cert):
    """The public-key algorithm name, or its dotted OID where asn1crypto has no name (GOST)."""
    info = cert["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"]
    return info.native if info.dotted != info.native else info.dotted


def attr_values(attrs, name):
    if attrs is None:
        return None
    for attr in attrs:
        if attr["type"].native == name:
            return attr["values"]
    return None


def signed_attrs_der(signer):
    """The signed attributes as signed: the [0] IMPLICIT encoding re-tagged as a SET."""
    raw = bytearray(signer["signed_attrs"].dump())
    raw[0] = 0x31
    return bytes(raw)


def tst_of(signer):
    values = attr_values(signer["unsigned_attrs"], OID_TST)
    if not values:
        return None
    token = values[0]
    return token


def tst_facts(token, signature):
    """Facts of an RFC 3161 token and whether its imprint covers `signature`."""
    sd = token["content"]
    tst = sd["encap_content_info"]["content"].parsed
    imprint = tst["message_imprint"]
    alg = imprint["hash_algorithm"]["algorithm"].native
    digest = imprint["hashed_message"].native
    hasher = DIGESTS.get(alg)
    covers = None
    if hasher is not None:
        covers = hasher[0](signature).digest() == digest
    return sd, {
        "gen_time": tst["gen_time"].native.isoformat(),
        "policy": tst["policy"].native,
        "imprint_alg": alg,
        "imprint_covers_signature": covers,
        "serial": tst["serial_number"].native,
    }


def rsa_check(sd, signer, content, rsa_certs_only=True):
    """Verify one signer's RSA signature and message digest. Returns a dict."""
    result = {}
    cert = find_cert(sd, signer["sid"])
    if cert is None:
        return {"error": "signer certificate not in the CMS"}
    alg = signer["digest_algorithm"]["algorithm"].native
    sig_alg = signer["signature_algorithm"]["algorithm"].native
    result["digest_alg"] = alg
    result["signature_alg"] = sig_alg
    if key_alg(cert) != "rsa":
        result["skipped"] = "non-RSA key (" + key_alg(cert) + ")"
        return result
    hasher = DIGESTS.get(alg)
    if hasher is None:
        result["skipped"] = "digest " + alg + " is not available here"
        return result
    attrs = signer["signed_attrs"]
    if attrs.native is None:
        message = content
        signed = content
        result["digest_ok"] = None
    else:
        md = attr_values(attrs, "message_digest")[0].native
        if content is None:
            return {"error": "no content to hash (detached)"}
        result["digest_ok"] = hasher[0](content).digest() == md
        signed = signed_attrs_der(signer)
    public = c_x509.load_der_x509_certificate(cert.dump()).public_key()
    try:
        public.verify(signer["signature"].native, signed, padding.PKCS1v15(), hasher[1]())
        result["signature_ok"] = True
    except InvalidSignature:
        result["signature_ok"] = False
    result["subject"] = cert.subject.human_friendly
    return result


def cmd_info(args):
    data, sd = load_signed_data(args.file)
    info = {"ok": True, "ber_indefinite": data[1:2] == b"\x80", "size": len(data)}
    info["version"] = sd["version"].native
    info["digest_algorithms"] = [a["algorithm"].native for a in sd["digest_algorithms"]]
    encap = sd["encap_content_info"]
    info["content_type"] = encap["content_type"].native
    content = encap["content"].native if encap["content"] is not None and encap["content"].native is not None else None
    info["attached"] = content is not None
    if content is not None:
        info["content_len"] = len(content)
        info["content_sha256"] = hashlib.sha256(content).hexdigest()
    info["certificates"] = len(certs_of(sd))
    info["crls"] = len(sd["crls"] or [])
    signers = []
    for signer in sd["signer_infos"]:
        entry = {
            "digest_alg": signer["digest_algorithm"]["algorithm"].native,
            "signature_alg": signer["signature_algorithm"]["algorithm"].native,
            "signed_attrs": [a["type"].native for a in (signer["signed_attrs"] or [])],
            "unsigned_attrs": [a["type"].native for a in (signer["unsigned_attrs"] or [])],
            "signature_hex": signer["signature"].native.hex(),
        }
        cert = find_cert(sd, signer["sid"])
        if cert is not None:
            entry["subject"] = cert.subject.human_friendly
            entry["key_algorithm"] = key_alg(cert)
        md = attr_values(signer["signed_attrs"], "message_digest")
        if md:
            entry["message_digest_hex"] = md[0].native.hex()
        st = attr_values(signer["signed_attrs"], OID_SIGNING_TIME)
        if st:
            entry["signing_time"] = st[0].native.isoformat()
        token = tst_of(signer)
        if token is not None:
            _, facts = tst_facts(token, signer["signature"].native)
            entry["timestamp"] = facts
        unsigned = signer["unsigned_attrs"] or []
        for attr in unsigned:
            name = attr["type"].native
            if name in ("revocation_values", "certificate_values", "ets_revocation_values", "ets_certificate_values", "cades_revocation_values"):
                entry.setdefault("evidence", {})[name] = len(attr["values"])
        signers.append(entry)
    info["signers"] = signers
    out(info)


def cmd_verify(args):
    data, sd = load_signed_data(args.file)
    content = None
    if args.content:
        content = read(args.content)
    else:
        encap = sd["encap_content_info"]["content"]
        if encap is not None and encap.native is not None:
            content = encap.native
    results = []
    all_ok = True
    for signer in sd["signer_infos"]:
        result = rsa_check(sd, signer, content)
        token = tst_of(signer)
        if token is not None:
            tsd, facts = tst_facts(token, signer["signature"].native)
            facts["signature"] = None
            tsa_signers = list(tsd["signer_infos"])
            if tsa_signers:
                # The token's own signature: over its signed attributes, RSA only.
                tcert = find_cert(tsd, tsa_signers[0]["sid"])
                # The signed bytes are the content octets of the TSTInfo, not its parsed form.
                tcontent = tsd["encap_content_info"]["content"].contents
                tr = rsa_check(tsd, tsa_signers[0], tcontent)
                facts["signature"] = tr
            result["timestamp"] = facts
        results.append(result)
        if result.get("signature_ok") is not True or result.get("digest_ok") is False:
            all_ok = False
    out({"ok": all_ok, "signers": results, "count": len(results)})


def cmd_digest(args):
    data, sd = load_signed_data(args.file)
    content = read(args.content)
    signer = list(sd["signer_infos"])[0]
    md = attr_values(signer["signed_attrs"], "message_digest")[0].native
    alg = signer["digest_algorithm"]["algorithm"].native
    if args.alg == "streebog512":
        import gostcrypto

        h = gostcrypto.gosthash.new("streebog512")
        h.update(content)
        digest = bytes(h.digest())
    elif args.alg in DIGESTS:
        digest = DIGESTS[args.alg][0](content).digest()
    else:
        out({"ok": False, "error": "no independent implementation of " + args.alg})
    out({"ok": digest == md, "digest_alg": alg, "message_digest": md.hex(), "independent": digest.hex()})


DS = "http://www.w3.org/2000/09/xmldsig#"
XA = "http://uri.etsi.org/01903/v1.3.2#"
C14N = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
    "http://www.w3.org/2006/12/xml-c14n11": (False, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
}
ENVELOPED = DS + "enveloped-signature"
XML_DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
XML_SIGNATURES = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "sha512",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "sha1",
}


def q(ns, name):
    return "{%s}%s" % (ns, name)


def parse_xml(path):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
    return etree.parse(path, parser)


def c14n(node, uri, prefixes=None):
    exclusive, comments = C14N[uri]
    kwargs = {}
    if exclusive and prefixes:
        kwargs["inclusive_ns_prefixes"] = prefixes
    return etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=comments, **kwargs)


def find_by_id(tree, ident):
    for el in tree.getroot().iter():
        if not isinstance(el.tag, str):
            continue
        for name, value in el.attrib.items():
            if value == ident and etree.QName(name).localname in ("Id", "ID", "id"):
                return el
    return None


def reference_bytes(tree, signature, reference):
    """The octets a Reference digests: dereference, apply the transforms."""
    uri = reference.get("URI")
    work = copy.deepcopy(tree)
    position = list(tree.getroot().iter(q(DS, "Signature"))).index(signature)
    sig_in_work = list(work.getroot().iter(q(DS, "Signature")))[position]
    if uri in (None, ""):
        target = work.getroot()
        whole_document = True
    elif uri.startswith("#"):
        target = find_by_id(work, uri[1:])
        whole_document = False
        if target is None:
            raise ValueError("unresolved reference " + uri)
    else:
        raise ValueError("external reference " + uri)
    c14n_uri, prefixes = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", None
    for transform in reference.findall("%s/%s" % (q(DS, "Transforms"), q(DS, "Transform"))):
        algorithm = transform.get("Algorithm")
        if algorithm == ENVELOPED:
            sig_in_work.getparent().remove(sig_in_work)
        elif algorithm in C14N:
            c14n_uri = algorithm
            inc = transform.find("{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces")
            if inc is not None and inc.get("PrefixList"):
                prefixes = inc.get("PrefixList").split()
        else:
            raise ValueError("unsupported transform " + algorithm)
    if whole_document:
        # A same-document reference with an empty URI covers the document without comments.
        target = work.getroot()
    return c14n(target, c14n_uri, prefixes), target


def signer_public_key(signature, cert_path):
    if cert_path:
        cert = c_x509.load_der_x509_certificate(read(cert_path))
    else:
        node = signature.find(".//" + q(DS, "X509Certificate"))
        if node is None:
            raise ValueError("no certificate to verify with")
        cert = c_x509.load_der_x509_certificate(base64.b64decode("".join(node.text.split())))
    return cert.public_key(), cert


def verify_one(tree, signature, cert_path):
    info = signature.find(q(DS, "SignedInfo"))
    method = info.find(q(DS, "SignatureMethod")).get("Algorithm")
    c14n_uri = info.find(q(DS, "CanonicalizationMethod")).get("Algorithm")
    result = {"signature_method": method, "references": []}
    for reference in info.findall(q(DS, "Reference")):
        entry = {"uri": reference.get("URI")}
        digest_uri = reference.find(q(DS, "DigestMethod")).get("Algorithm")
        digest_name = XML_DIGESTS.get(digest_uri)
        try:
            octets, target = reference_bytes(tree, signature, reference)
            entry["signed_element"] = etree.QName(target).localname if isinstance(target.tag, str) else "?"
            if digest_name is None:
                entry["skipped"] = "digest " + digest_uri
            else:
                expected = base64.b64decode("".join(reference.find(q(DS, "DigestValue")).text.split()))
                entry["digest_ok"] = hashlib.new(digest_name, octets).digest() == expected
        except Exception as error:  # noqa: BLE001
            entry["error"] = "%s: %s" % (type(error).__name__, error)
        result["references"].append(entry)
    value = base64.b64decode("".join(signature.find(q(DS, "SignatureValue")).text.split()))
    hash_name = XML_SIGNATURES.get(method)
    if hash_name is None:
        result["signed_info"] = "skipped(" + method + ")"
    else:
        public, cert = signer_public_key(signature, cert_path)
        try:
            public.verify(value, c14n(info, c14n_uri), padding.PKCS1v15(), DIGESTS[hash_name][1]())
            result["signed_info"] = "ok"
        except InvalidSignature:
            result["signed_info"] = "bad"
    return result


def cmd_xmldsig(args):
    tree = parse_xml(args.file)
    signatures = list(tree.getroot().iter(q(DS, "Signature")))
    results = [verify_one(tree, s, args.cert) for s in signatures]
    ok = bool(results) and all(
        r["signed_info"] == "ok"
        and r["references"]
        and all(ref.get("digest_ok") is True for ref in r["references"])
        for r in results
    )
    out({"ok": ok, "count": len(results), "signatures": results})


PDF_SIG_RE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


def pdf_signatures(path):
    """(byte_range, contents_hex_span) of every signature dictionary, from the raw bytes."""
    data = read(path)
    found = []
    for m in PDF_SIG_RE.finditer(data):
        a, b, c, d = (int(g) for g in m.groups())
        # /Contents <hex> sits between the two ranges: the gap [a+b, c) is `<hex...>`.
        gap = data[a + b : c]
        found.append(((a, b, c, d), gap))
    return data, found


def cmd_pdf_byterange(args):
    data, found = pdf_signatures(args.file)
    size = len(data)
    results = []
    for (a, b, c, d), gap in found:
        entry = {"byte_range": [a, b, c, d], "file_size": size}
        entry["structure_ok"] = (
            a == 0 and b > 0 and c > a + b and d >= 0 and c + d <= size and gap.startswith(b"<") and gap.endswith(b">")
        )
        entry["covers_to_end"] = c + d == size
        hexdigits = gap.strip()[1:-1]
        raw = bytes.fromhex(hexdigits.decode("ascii"))
        # Trailing zero padding of the reserved space is not part of the CMS.
        info = cms.ContentInfo.load(raw)
        sd = info["content"]
        signer = list(sd["signer_infos"])[0]
        alg = signer["digest_algorithm"]["algorithm"].native
        entry["digest_alg"] = alg
        md = attr_values(signer["signed_attrs"], "message_digest")[0].native
        sm0 = re.search(rb"/SubFilter\s*/([A-Za-z0-9_.]+)", data[max(0, a + b - 600) : a + b + 80]) or re.search(rb"/SubFilter\s*/([A-Za-z0-9_.]+)", data[c : c + 200])
        if sm0 and sm0.group(1) == b"ETSI.RFC3161":
            # A document timestamp: the token's imprint covers the ranges.
            tsd = sd
            tst = tsd["encap_content_info"]["content"].parsed
            imprint_alg = tst["message_imprint"]["hash_algorithm"]["algorithm"].native
            want = tst["message_imprint"]["hashed_message"].native
            h = DIGESTS[imprint_alg][0]()
            h.update(data[a : a + b])
            h.update(data[c : c + d])
            entry["doc_timestamp"] = True
            entry["subfilter"] = "ETSI.RFC3161"
            entry["digest_ok"] = h.digest() == want
            tr = rsa_check(tsd, signer, tsd["encap_content_info"]["content"].contents)
            entry["signature_ok"] = tr.get("signature_ok")
            entry["signature_note"] = tr.get("skipped")
            results.append(entry)
            continue
        hasher = DIGESTS.get(alg)
        if alg == "1.2.398.3.10.1.3.3":
            import gostcrypto

            g = gostcrypto.gosthash.new("streebog512")
            g.update(data[a : a + b])
            g.update(data[c : c + d])
            entry["byterange_digest"] = bytes(g.digest()).hex()
            entry["message_digest"] = md.hex()
            entry["digest_ok"] = bytes(g.digest()) == md
            entry["signature_note"] = "GOST signature: judged by NCANode only"
        elif hasher is not None:
            h = hasher[0]()
            h.update(data[a : a + b])
            h.update(data[c : c + d])
            entry["byterange_digest"] = h.hexdigest()
            entry["message_digest"] = md.hex()
            entry["digest_ok"] = h.digest() == md
            result = rsa_check(sd, signer, data[a : a + b] + data[c : c + d])
            entry["signature_ok"] = result.get("signature_ok")
            entry["signature_note"] = result.get("skipped")
        else:
            entry["message_digest"] = md.hex()
            entry["digest_ok"] = None
            entry["signature_note"] = "digest " + alg + " not available here"
        token = tst_of(signer)
        if token is not None:
            _, facts = tst_facts(token, signer["signature"].native)
            entry["timestamp"] = facts
        sub = None
        # The enclosing dictionary names the SubFilter just before /ByteRange or after /Contents.
        window = data[max(0, a + b - 600) : a + b + 80]
        sm = re.search(rb"/SubFilter\s*/([A-Za-z0-9_.]+)", window) or re.search(rb"/SubFilter\s*/([A-Za-z0-9_.]+)", data[c : c + 200])
        entry["subfilter"] = sm.group(1).decode() if sm else None
        results.append(entry)
    ok = bool(results) and all(
        r["structure_ok"] and r.get("digest_ok") is not False and r.get("signature_ok") is not False for r in results
    )
    out({"ok": ok, "signatures": results})


def cmd_pdf_verify(args):
    import asyncio

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
    from pyhanko.sign.validation.dss import DocumentSecurityStore, NoDSSFoundError
    from pyhanko_certvalidator import ValidationContext

    root = asn1_x509.Certificate.load(read(args.root))
    when = datetime.datetime.fromtimestamp(int(args.at), datetime.timezone.utc)
    result = {"signatures": [], "doc_timestamps": 0, "dss": None}
    with open(args.file, "rb") as handle:
        reader = PdfFileReader(handle)
        try:
            dss = DocumentSecurityStore.read_dss(reader)
            result["dss"] = {"certs": len(dss.certs), "ocsps": len(dss.ocsps), "crls": len(dss.crls), "vri": len(dss.vri_entries)}
        except NoDSSFoundError:
            dss = None
        kwargs = {"trust_roots": [root], "allow_fetching": False, "revocation_mode": args.revocation, "moment": when}

        def context():
            if dss is not None:
                return dss.as_validation_context(kwargs)
            return ValidationContext(**kwargs)

        ok = True
        for emb in reader.embedded_signatures:
            is_ts = str(emb.sig_object.get("/Type")) == "/DocTimeStamp"
            item = {"timestamp": is_ts, "field": emb.field_name}
            try:
                if is_ts:
                    result["doc_timestamps"] += 1
                    status = validate_pdf_timestamp(emb, validation_context=context())
                else:
                    status = validate_pdf_signature(emb, signer_validation_context=context(), ts_validation_context=context())
                item.update(
                    intact=bool(status.intact),
                    valid=bool(status.valid),
                    trusted=bool(status.trusted),
                    coverage=str(status.coverage),
                    bottom_line=bool(status.intact and status.valid and status.trusted),
                )
                ok = ok and bool(status.intact and status.valid and status.trusted)
            except Exception as error:  # noqa: BLE001
                item["error"] = "%s: %s" % (type(error).__name__, str(error)[:300])
                ok = False
            result["signatures"].append(item)
    result["ok"] = ok and bool(result["signatures"])
    out(result)


def cmd_xades(args):
    tree = parse_xml(args.file)
    root = tree.getroot()
    info = {"ok": True}
    signature = root.find(".//" + q(DS, "Signature"))
    if signature is None:
        out({"ok": False, "error": "no signature"})
    _, cert = signer_public_key(signature, None)
    sc = root.find(".//" + q(XA, "SigningCertificateV2"))
    if sc is None:
        sc = root.find(".//" + q(XA, "SigningCertificate"))
    if sc is not None:
        digest = sc.find(".//" + q(XA, "DigestValue"))
        if digest is None:
            digest = sc.find(".//" + q(DS, "DigestValue"))
        method = sc.find(".//" + q(DS, "DigestMethod")).get("Algorithm")
        name = XML_DIGESTS.get(method, "sha256")
        want = base64.b64decode("".join(digest.text.split()))
        info["signing_certificate_digest_ok"] = hashlib.new(name, cert.public_bytes(serialization.Encoding.DER)).digest() == want
    sv = signature.find(q(DS, "SignatureValue"))
    sig_c14n = c14n(sv, "http://www.w3.org/2001/10/xml-exc-c14n#")
    info["signature_timestamps"] = []
    for ts in root.iter(q(XA, "SignatureTimeStamp")):
        enc = ts.find(q(XA, "EncapsulatedTimeStamp"))
        method = ts.find(q(DS, "CanonicalizationMethod"))
        uri = method.get("Algorithm") if method is not None else "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        covered = c14n(sv, uri)
        token = cms.ContentInfo.load(base64.b64decode("".join(enc.text.split())))
        tsd, facts = tst_facts(token, covered)
        tsa_signers = list(tsd["signer_infos"])
        tr = rsa_check(tsd, tsa_signers[0], tsd["encap_content_info"]["content"].contents)
        facts["signature"] = tr
        info["signature_timestamps"].append(facts)
    info["certificate_values"] = len(list(root.iter(q(XA, "EncapsulatedX509Certificate"))))
    info["ocsp_values"] = len(list(root.iter(q(XA, "EncapsulatedOCSPValue"))))
    info["crl_values"] = len(list(root.iter(q(XA, "EncapsulatedCRLValue"))))
    info["archive_timestamps"] = len([e for e in root.iter() if isinstance(e.tag, str) and etree.QName(e).localname == "ArchiveTimeStamp"])
    out(info)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("cms-info")
    p.add_argument("file")
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser("cms-verify")
    p.add_argument("file")
    p.add_argument("--content")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("cms-digest")
    p.add_argument("file")
    p.add_argument("--content", required=True)
    p.add_argument("--alg", required=True)
    p.set_defaults(fn=cmd_digest)
    p = sub.add_parser("xmldsig-verify")
    p.add_argument("file")
    p.add_argument("--cert")
    p.set_defaults(fn=cmd_xmldsig)
    p = sub.add_parser("pdf-byterange")
    p.add_argument("file")
    p.set_defaults(fn=cmd_pdf_byterange)
    p = sub.add_parser("pdf-verify")
    p.add_argument("file")
    p.add_argument("--root", required=True)
    p.add_argument("--at", required=True)
    p.add_argument("--revocation", default="soft-fail")
    p.set_defaults(fn=cmd_pdf_verify)
    p = sub.add_parser("xades-info")
    p.add_argument("file")
    p.set_defaults(fn=cmd_xades)
    args = parser.parse_args()
    try:
        args.fn(args)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001
        if os.environ.get("ONCL_ORACLE_TRACE"):
            raise
        out({"ok": False, "error": "%s: %s" % (type(error).__name__, error)})


main()
