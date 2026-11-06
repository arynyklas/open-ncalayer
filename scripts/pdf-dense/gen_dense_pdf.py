#!/usr/bin/env python3
"""Independent generator of dense, content-rich PDFs (no PDF library, no oncl code).

    gen_dense_pdf.py OUT.pdf --objects 1000000 [--mode classic|stream] [--revisions 3]

The document has a two-level page tree (nodes of 200 pages) so that no single object
is large: with N objects there are about N/2 pages, each with its own small content
stream. `--mode stream` stores the page tree and pages in object streams (100 objects
each) and uses cross-reference streams (W [1 4 2], Flate + PNG up predictor).
`--revisions R` appends R-1 incremental updates, each re-writing one page object and
listing only that object in its xref section (the common real-world shape).

Prints one JSON line: {"objects": <highest object number + 1>, "pages": ..., "revisions": ...}
"""
import argparse
import json
import struct
import sys
import zlib

PER_NODE = 200
PER_OBJSTM = 100


def pages_layout(objects):
    """Object numbers: 1 catalog, 2 pages root, then nodes, then (page, content) pairs."""
    pages = max(1, (objects - 2) // 2)
    nodes = (pages + PER_NODE - 1) // PER_NODE
    pages = max(1, (objects - 2 - nodes) // 2)
    nodes = (pages + PER_NODE - 1) // PER_NODE
    return pages, nodes


def build_objects(objects):
    pages, nodes = pages_layout(objects)
    first_node = 3
    first_page = first_node + nodes
    body = {}  # number -> (kind, bytes) kind: 'obj' or 'stream'
    body[1] = ("obj", b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = b" ".join(b"%d 0 R" % (first_node + i) for i in range(nodes))
    body[2] = ("obj", b"<< /Type /Pages /Count %d /Kids [%s] >>" % (pages, kids))
    for n in range(nodes):
        lo, hi = n * PER_NODE, min(pages, (n + 1) * PER_NODE)
        pk = b" ".join(b"%d 0 R" % (first_page + 2 * p) for p in range(lo, hi))
        body[first_node + n] = (
            "obj",
            b"<< /Type /Pages /Parent 2 0 R /Count %d /Kids [%s] >>" % (hi - lo, pk),
        )
    for p in range(pages):
        pid = first_page + 2 * p
        node = first_node + p // PER_NODE
        body[pid] = (
            "obj",
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Contents %d 0 R >>"
            % (node, pid + 1),
        )
        text = b"BT /F1 12 Tf 72 720 Td (page %d) Tj ET" % p
        body[pid + 1] = ("stream", text)
    return body, pages, nodes, first_page


def classic_obj(num, kind, data):
    if kind == "stream":
        return b"%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n" % (
            num,
            len(data),
            data,
        )
    return b"%d 0 obj\n%s\nendobj\n" % (num, data)


def classic_xref(entries, prev):
    """entries: sorted list of (num, offset). One subsection per consecutive run."""
    out = bytearray(b"xref\n")
    if prev is None:
        out += b"0 1\n0000000000 65535 f \n"
    runs = []
    run = []
    for num, off in entries:
        if run and num != run[-1][0] + 1:
            runs.append(run)
            run = []
        run.append((num, off))
    if run:
        runs.append(run)
    for r in runs:
        out += b"%d %d\n" % (r[0][0], len(r))
        for _, off in r:
            out += b"%010d 00000 n \n" % off
    return bytes(out)


def png_up(raw, width):
    out = bytearray()
    prev = bytes(width)
    for i in range(0, len(raw), width):
        row = raw[i : i + width]
        out.append(2)
        out += bytes((row[j] - prev[j]) & 255 for j in range(width))
        prev = row
    return bytes(out)


def write_classic(path, objects, revisions):
    body, pages, nodes, first_page = build_objects(objects)
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(body):
        offsets[num] = len(out)
        out += classic_obj(num, *body[num])
    size = max(body) + 1
    startxref = len(out)
    entries = sorted(offsets.items())
    out += classic_xref(entries, None)
    out += b"trailer\n<< /Size %d /Root 1 0 R /ID [<%s> <%s>] >>\n" % (
        size,
        b"11" * 16,
        b"11" * 16,
    )
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    prev = startxref
    for rev in range(1, revisions):
        num = first_page + 2 * (rev - 1)
        off = len(out)
        out += classic_obj(
            num,
            "obj",
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Rotate 0 >>"
            % (3 + (rev - 1) // PER_NODE, num + 1),
        )
        sx = len(out)
        out += classic_xref([(num, off)], prev)
        out += b"trailer\n<< /Size %d /Root 1 0 R /Prev %d /ID [<%s> <%s>] >>\n" % (
            size,
            prev,
            b"11" * 16,
            b"11" * 16,
        )
        out += b"startxref\n%d\n%%%%EOF\n" % sx
        prev = sx
    with open(path, "wb") as f:
        f.write(out)
    return size, pages


def write_stream(path, objects, revisions):
    body, pages, nodes, first_page = build_objects(objects)
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    rows = {}  # num -> (type, f2, f3)
    # Streams (content) stay direct; everything else goes into object streams.
    direct = [n for n in sorted(body) if body[n][0] == "stream"]
    packed = [n for n in sorted(body) if body[n][0] == "obj"]
    for num in direct:
        rows[num] = (1, len(out), 0)
        out += classic_obj(num, *body[num])
    size = max(body) + 1
    nextnum = size
    for i in range(0, len(packed), PER_OBJSTM):
        chunk = packed[i : i + PER_OBJSTM]
        header = bytearray()
        data = bytearray()
        for idx, num in enumerate(chunk):
            header += b"%d %d " % (num, len(data))
            data += body[num][1] + b"\n"
            rows[num] = (2, nextnum, idx)
        payload = zlib.compress(bytes(header) + bytes(data))
        rows[nextnum] = (1, len(out), 0)
        out += (
            b"%d 0 obj\n<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n"
            % (nextnum, len(chunk), len(header), len(payload))
            + payload
            + b"\nendstream\nendobj\n"
        )
        nextnum += 1
    xnum = nextnum
    size = xnum + 1
    startxref = len(out)
    rows[xnum] = (1, startxref, 0)
    rows[0] = (0, 0, 65535)
    raw = b"".join(
        struct.pack(">BIH", rows[n][0], rows[n][1], rows[n][2]) for n in range(size)
    )
    payload = zlib.compress(png_up(raw, 7))
    out += (
        b"%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /ID [<%s> <%s>] "
        b"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> /Length %d >>\nstream\n"
        % (xnum, size, b"11" * 16, b"11" * 16, len(payload))
        + payload
        + b"\nendstream\nendobj\n"
    )
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    prev = startxref
    for rev in range(1, revisions):
        num = first_page + 2 * (rev - 1)  # a page was packed: re-write it directly
        off = len(out)
        out += classic_obj(
            num,
            "obj",
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Rotate 0 >>"
            % (3 + (rev - 1) // PER_NODE, num + 1),
        )
        xnum2 = size
        size += 1
        sx = len(out)
        raw = struct.pack(">BIH", 1, off, 0) + struct.pack(">BIH", 1, sx, 0)
        payload = zlib.compress(png_up(raw, 7))
        out += (
            b"%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Index [%d 1 %d 1] /Root 1 0 R /Prev %d "
            b"/ID [<%s> <%s>] /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> "
            b"/Length %d >>\nstream\n"
            % (xnum2, size, num, xnum2, prev, b"11" * 16, b"11" * 16, len(payload))
            + payload
            + b"\nendstream\nendobj\n"
        )
        out += b"startxref\n%d\n%%%%EOF\n" % sx
        prev = sx
    with open(path, "wb") as f:
        f.write(out)
    return size, pages


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--objects", type=int, required=True)
    ap.add_argument("--mode", choices=["classic", "stream"], default="classic")
    ap.add_argument("--revisions", type=int, default=1)
    a = ap.parse_args()
    fn = write_classic if a.mode == "classic" else write_stream
    size, pages = fn(a.out, a.objects, a.revisions)
    print(json.dumps({"objects": size, "pages": pages, "revisions": a.revisions}))


if __name__ == "__main__":
    sys.exit(main())
