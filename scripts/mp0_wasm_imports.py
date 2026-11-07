#!/usr/bin/env python3
"""MP0 inventory: host imports of each plugin port, read from the wasm import section.

Usage: python scripts/mp0_wasm_imports.py <dir-with-oncl_port_*.wasm> [--json]

Build the wasm first (from the repo root):
    cd plugins && cargo build --release --locked --target wasm32-unknown-unknown --workspace
and pass <target>/wasm32-unknown-unknown/release.  Imports are the entries of module "oncl"
(`oncl_pdk::abi::IMPORT_MODULE`), named as `Import::name()`; the order is that of the section,
as `Compiled::imports()` returns it.  Only the standard library is used.
"""
import glob, json, os, sys


def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s; s += 7
        if not x & 0x80:
            return r, i


def imports(path):
    b = open(path, "rb").read()
    assert b[:4] == b"\0asm"
    i, out = 8, []
    while i < len(b):
        sid = b[i]; size, j = leb(b, i + 1); end = j + size
        if sid == 2:
            n, k = leb(b, j)
            for _ in range(n):
                ln, k = leb(b, k); mod = b[k:k + ln].decode(); k += ln
                ln, k = leb(b, k); name = b[k:k + ln].decode(); k += ln
                kind = b[k]; k += 1
                if kind == 0: _, k = leb(b, k)
                elif kind == 1: k += 1; f = b[k]; k += 1; _, k = leb(b, k); (f & 1) and leb(b, k)[1]
                elif kind == 2: f = b[k]; k += 1; _, k = leb(b, k); k = leb(b, k)[1] if f & 1 else k
                elif kind == 3: k += 2
                out.append((mod, name))
        i = end
    return out


if __name__ == "__main__":
    d = sys.argv[1]
    res = {}
    for p in sorted(glob.glob(os.path.join(d, "oncl_port_*.wasm"))):
        port = os.path.basename(p)[len("oncl_port_"):-5].replace("_", "-")
        ims = imports(p)
        bad = [m for m, _ in ims if m != "oncl"]
        assert not bad, (port, bad)
        res[port] = [n for _, n in ims]
    if "--json" in sys.argv:
        json.dump(res, sys.stdout, indent=1)
    else:
        for k, v in res.items():
            print(k, len(v), " ".join(v))
