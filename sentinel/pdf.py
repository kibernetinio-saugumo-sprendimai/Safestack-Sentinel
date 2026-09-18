"""Small dependency-free, print-ready PDF exporter."""
from pathlib import Path
from .safeio import atomic_write

def write_pdf(report: dict, path: str) -> None:
    lines = ["SafeStack Sentinel", f"Score: {report['score']}", f"Generated: {report['generated_at']}", ""]
    for f in report["findings"]:
        lines.append(f"{f['check']} [{f['severity']}/{f['status']}]: {f['summary']}")
    lines = [line.encode("ascii", "replace").decode("ascii")[:110] for line in lines]
    stream = "BT\n/F1 10 Tf\n50 780 Td\n" + "\n".join(f"({line.replace(chr(92), chr(92)+chr(92)).replace('(', chr(92)+'(').replace(')', chr(92)+')')}) Tj 0 -16 Td" for line in lines) + "\nET"
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream"]
    out = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"; offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out.encode())); out += f"{i} 0 obj\n{obj}\nendobj\n"
    xref = len(out.encode()); out += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n" + "".join(f"{n:010d} 00000 n \n" for n in offsets[1:])
    out += f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    atomic_write(path, out.encode("latin-1"), 0o600)
