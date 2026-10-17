"""Writes a small, valid one-page PDF fixture (PoC A4). Usage: make_pdf.py OUT"""

import sys

content = (
    b"BT /F1 28 Tf 72 720 Td (Simulation-Rift PoC A4) Tj ET\n"
    b"BT /F1 14 Tf 72 690 Td (Rendered inside an isolatedProcess worker.) Tj ET\n"
    b"0 0 1 RG 6 w 72 600 m 540 600 l S\n"
)
objects = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
    b"/Resources << /Font << /F1 5 0 R >> >> >>",
    b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
]

out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
offsets = []
for number, body in enumerate(objects, start=1):
    offsets.append(len(out))
    out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
xref = len(out)
out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
for offset in offsets:
    out += b"%010d 00000 n \n" % offset
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)

with open(sys.argv[1], "wb") as f:
    f.write(out)
