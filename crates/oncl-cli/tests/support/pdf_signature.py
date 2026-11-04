"""Independent PDF signature extraction (stdlib only).

usage: pdf_signature.py SIGNED.pdf OUT_SIGNED_BYTES OUT_CMS_DER
Finds the last /ByteRange, writes exactly the bytes it covers and the CMS in
/Contents (hex, trailing zero padding stripped), and prints
`BYTERANGE a b c d FILELEN n GAP g`.
"""
import re
import sys

data = open(sys.argv[1], "rb").read()
matches = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))
if not matches:
    sys.exit("no ByteRange")
a, b, c, d = (int(x) for x in matches[-1].groups())
assert a == 0, "ByteRange must start at 0"
assert b <= c <= len(data), "gap inside the file"
assert c + d == len(data), "ByteRange must end at end of file (%d != %d)" % (c + d, len(data))
gap = data[b:c]
assert gap[:1] == b"<" and gap[-1:] == b">", "gap must be exactly the hex <Contents>"
hexdata = gap[1:-1]
cms = bytes.fromhex(hexdata.decode())
# strip DER-external zero padding using the outer SEQUENCE length
assert cms[0] == 0x30
if cms[1] & 0x80:
    n = cms[1] & 0x7F
    length = int.from_bytes(cms[2:2 + n], "big") + 2 + n
else:
    length = cms[1] + 2
open(sys.argv[2], "wb").write(data[:b] + data[c:])
open(sys.argv[3], "wb").write(cms[:length])
print("BYTERANGE", a, b, c, d, "FILELEN", len(data), "GAP", len(gap))
