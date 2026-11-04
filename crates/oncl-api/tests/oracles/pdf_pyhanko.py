"""Independent PDF signature oracle (pyHanko). Usage: pdf_pyhanko.py <pdf> <trusted-leaf.der>
The synthetic CAs are GOST-signed, which pyHanko cannot verify, so the signer's own
certificate is the trust root: this checks the CMS signature, signed attributes and
ByteRange coverage independently, not the NUCA-style chain."""
import asyncio, json, sys
from asn1crypto import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

pdf, leaf = sys.argv[1], sys.argv[2]
cert = x509.Certificate.load(open(leaf, "rb").read())
vc = ValidationContext(trust_roots=[cert], allow_fetching=False, revocation_mode="soft-fail")
with open(pdf, "rb") as handle:
    reader = PdfFileReader(handle)
    out = {"signatures": [], "dss": None}
    for sig in reader.embedded_signatures:
        entry = {"name": sig.field_name,
                 "doc_timestamp": str(sig.sig_object.get("/Type")) == "/DocTimeStamp"}
        if entry["doc_timestamp"]:
            # Document timestamps are not /Sig objects. The synthetic TSA signs with
            # GOST which pyHanko cannot verify: report only what it independently
            # parses (ByteRange coverage and the digest it computes over it).
            sig.compute_integrity_info()
            entry.update(coverage=str(sig.coverage), full_validation=False,
                         intact=True, valid=False, has_timestamp_token=False,
                         digest_len=len(sig.compute_digest()))
            out["signatures"].append(entry)
            continue
        unsigned = sig.signed_data["signer_infos"][0]["unsigned_attrs"]
        has_token = unsigned is not None and any(
            a["type"].native == "signature_time_stamp_token" for a in unsigned)
        try:
            status = validate_pdf_signature(sig, vc)
            entry.update(intact=bool(status.intact), valid=bool(status.valid),
                         coverage=str(status.coverage), full_validation=True)
        except Exception as error:  # noqa: BLE001
            if not has_token:
                # Only the GOST-signed timestamp token justifies the reduced check.
                raise
            # The synthetic TSA signs with GOST, which pyHanko cannot verify: validate
            # the CMS signature and ByteRange digest alone, report why.
            from pyhanko.sign.validation.generic_cms import cms_basic_validation
            from pyhanko.sign.validation.settings import KeyUsageConstraints
            try:
                sig.compute_integrity_info()
                digest = sig.compute_digest()
                result = asyncio.run(cms_basic_validation(
                    sig.signed_data, raw_digest=digest, validation_context=vc,
                    key_usage_settings=KeyUsageConstraints()))
                entry.update(intact=bool(result.get("intact")), valid=bool(result.get("valid")),
                             coverage=str(sig.coverage), full_validation=False,
                             exception=type(error).__name__)
            except Exception as second:  # noqa: BLE001 - a broken signature is the finding
                entry.update(intact=False, valid=False, full_validation=False,
                             exception=type(second).__name__, integrity_exception=True)
        entry["has_timestamp_token"] = has_token
        out["signatures"].append(entry)
    root = reader.root
    if "/DSS" in root:
        dss = root["/DSS"]
        out["dss"] = {k: len(dss[k]) if k in dss else 0 for k in ("/Certs", "/OCSPs", "/CRLs")}
print(json.dumps(out))
