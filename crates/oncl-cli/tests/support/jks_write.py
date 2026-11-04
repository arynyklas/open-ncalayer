"""Test-only Sun JKS (version 2) writer, independent of the SDK (hashlib only).

usage: jks_write.py OUT.jks ALIAS PASSWORD PKCS8.der CERT.der [CERT.der ...]
One private-key entry: key protected with Sun's KeyProtector (SHA-1 keystream XOR
over the PKCS#8, 20-byte random salt, trailing SHA-1(password || PKCS#8)), the
certificate chain, and the file digest SHA-1(password || "Mighty Aphrodite" || body).
"""
import hashlib
import os
import struct
import sys

out, alias, password, pkcs8_path = sys.argv[1:5]
cert_paths = sys.argv[5:]
passwd = password.encode("utf-16-be")
pkcs8 = open(pkcs8_path, "rb").read()

def tlv(tag, body):
    if len(body) < 128:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body

salt = os.urandom(20)
stream, block, encrypted = b"", salt, bytearray()
for i in range(0, len(pkcs8), 20):
    block = hashlib.sha1(passwd + block).digest()
    encrypted += bytes(a ^ b for a, b in zip(pkcs8[i:i + 20], block))
protected = salt + bytes(encrypted) + hashlib.sha1(passwd + pkcs8).digest()
# EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier(1.3.6.1.4.1.42.2.17.1.1, NULL), OCTET STRING }
oid = bytes.fromhex("060a2b060104012a02110101")
algorithm = tlv(0x30, oid + b"\x05\x00")
info = tlv(0x30, algorithm + tlv(0x04, protected))

def utf(text):
    raw = text.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw

body = struct.pack(">III", 0xFEEDFEED, 2, 1)
body += struct.pack(">I", 1) + utf(alias) + struct.pack(">Q", 1735689600000)
body += struct.pack(">I", len(info)) + info
body += struct.pack(">I", len(cert_paths))
for path in cert_paths:
    cert = open(path, "rb").read()
    body += utf("X.509") + struct.pack(">I", len(cert)) + cert
body += hashlib.sha1(passwd + b"Mighty Aphrodite" + body).digest()
open(out, "wb").write(body)
