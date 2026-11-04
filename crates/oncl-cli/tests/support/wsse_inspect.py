"""Independent structural view of a signed SOAP envelope (lxml only).

usage: wsse_inspect.py SIGNED.xml   -> one JSON document on stdout
"""
import base64
import json
import sys

from lxml import etree

NS = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
}
WSU = "{%s}Id" % NS["wsu"]
SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"

root = etree.parse(sys.argv[1]).getroot()
out = {"envelope_ns": etree.QName(root).namespace}
soap = out["envelope_ns"]
body = root.find("{%s}Body" % soap)
out["body_id"] = body.get(WSU)
security = root.find("{%s}Header/wsse:Security" % soap, NS)
out["security_actor"] = security.get("{%s}actor" % SOAP11)
out["security_role"] = security.get("{%s}role" % SOAP12)
bst = security.find("wsse:BinarySecurityToken", NS)
if bst is not None:
    out["bst"] = {
        "id": bst.get(WSU),
        "value_type": bst.get("ValueType"),
        "encoding_type": bst.get("EncodingType"),
        "der_hex": base64.b64decode(bst.text).hex(),
    }
ts = security.find("wsu:Timestamp", NS)
if ts is not None:
    out["timestamp"] = {
        "id": ts.get(WSU),
        "created": ts.findtext("wsu:Created", namespaces=NS),
        "expires": ts.findtext("wsu:Expires", namespaces=NS),
    }
signature = security.find("ds:Signature", NS)
out["references"] = [r.get("URI") for r in signature.findall("ds:SignedInfo/ds:Reference", NS)]
str_ref = signature.find("ds:KeyInfo/wsse:SecurityTokenReference", NS)
key_id = str_ref.find("wsse:KeyIdentifier", NS)
ref = str_ref.find("wsse:Reference", NS)
out["key_reference"] = {
    "key_identifier_value_type": None if key_id is None else key_id.get("ValueType"),
    "reference_uri": None if ref is None else ref.get("URI"),
    "reference_value_type": None if ref is None else ref.get("ValueType"),
}
signed_header_ids = [
    h.get(WSU) for h in root.findall("{%s}Header/*" % soap) if h is not security
]
out["other_header_ids"] = signed_header_ids
print(json.dumps(out))
