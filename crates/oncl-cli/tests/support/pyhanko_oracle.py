"""Independent PAdES oracle (pyHanko): signature integrity, DSS contents, DocTimeStamp,
and validation from DSS-only revocation material with revocation REQUIRED.

usage: pyhanko_oracle.py SIGNED.pdf ROOT.der MOMENT_UNIX
Prints one JSON document. Exit 2 when anything is not intact/valid/trusted.
"""
import datetime
import json
import sys
import asyncio

from asn1crypto import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko.sign.validation.dss import DocumentSecurityStore, NoDSSFoundError
from pyhanko_certvalidator.registry import SimpleCertificateStore  # noqa: F401

pdf_path, root_path, moment = sys.argv[1], sys.argv[2], int(sys.argv[3])
root = x509.Certificate.load(open(root_path, "rb").read())
when = datetime.datetime.fromtimestamp(moment, datetime.timezone.utc)
reader = PdfFileReader(open(pdf_path, "rb"))
out = {"signatures": 0, "doc_timestamps": 0, "dss": None, "results": []}
try:
    dss = DocumentSecurityStore.read_dss(reader)
    out["dss"] = {"certs": len(dss.certs), "ocsps": len(dss.ocsps), "crls": len(dss.crls), "vri": len(dss.vri_entries)}
except NoDSSFoundError:
    dss = None
kwargs = {"trust_roots": [root], "allow_fetching": False, "revocation_mode": "require", "moment": when}
def context():
    if dss is not None:
        return dss.as_validation_context(kwargs)
    from pyhanko_certvalidator import ValidationContext
    return ValidationContext(**kwargs)
bad = False
for emb in reader.embedded_signatures:
    is_ts = emb.sig_object.get("/Type") == "/DocTimeStamp"
    try:
        if is_ts:
            out["doc_timestamps"] += 1
            status = validate_pdf_timestamp(emb, validation_context=context())
        else:
            out["signatures"] += 1
            status = validate_pdf_signature(emb, signer_validation_context=context(), ts_validation_context=context())
        item = {"timestamp": is_ts, "intact": status.intact, "valid": status.valid, "trusted": status.trusted, "bottom_line": bool(status.intact and status.valid and status.trusted)}
        bad |= not item["bottom_line"]
    except Exception as error:  # noqa: BLE001
        item = {"timestamp": is_ts, "error": "%s: %s" % (type(error).__name__, error)}
        bad = True
    out["results"].append(item)
print(json.dumps(out))
sys.exit(2 if bad or (out["signatures"] + out["doc_timestamps"]) == 0 else 0)
