"""Build small synthetic PDFs for tests (no third-party writer needed). Content is invented test text, not report data."""
from __future__ import annotations


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(pages: list[list[str]], title: str | None = None, author: str | None = None,
             outline: list[tuple[str, int]] | None = None) -> bytes:
    """pages: list of pages, each a list of text lines (an empty list makes an image-like page with no text).
    outline: (title, 1-based page) bookmarks, all at level 1."""
    objs: list[bytes] = []

    def add(b: str | bytes) -> int:
        objs.append(b.encode("latin-1") if isinstance(b, str) else b)
        return len(objs)

    catalog = add("")  # placeholder
    pages_obj = add("")
    font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []
    for lines in pages:
        ops = ["BT", "/F1 11 Tf", "14 TL", "72 760 Td"]
        for ln in lines:
            ops.append(f"({_esc(ln)}) Tj T*")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page_ids.append(add(f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 612 792] "
                            f"/Resources << /Font << /F1 {font} 0 R >> >> /Contents {content} 0 R >>"))
    objs[pages_obj - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {len(page_ids)} >>".encode()
    cat = f"<< /Type /Catalog /Pages {pages_obj} 0 R"
    if outline:
        root = add("")
        items = []
        for _ in outline:
            items.append(add(""))
        for i, (t, pg) in enumerate(outline):
            parts = [f"/Title ({_esc(t)})", f"/Parent {root} 0 R", f"/Dest [{page_ids[pg - 1]} 0 R /Fit]"]
            if i > 0:
                parts.append(f"/Prev {items[i - 1]} 0 R")
            if i < len(items) - 1:
                parts.append(f"/Next {items[i + 1]} 0 R")
            objs[items[i] - 1] = ("<< " + " ".join(parts) + " >>").encode("latin-1")
        objs[root - 1] = f"<< /Type /Outlines /First {items[0]} 0 R /Last {items[-1]} 0 R /Count {len(items)} >>".encode()
        cat += f" /Outlines {root} 0 R"
    objs[catalog - 1] = (cat + " >>").encode()
    info = None
    if title or author:
        fields = (f"/Title ({_esc(title)}) " if title else "") + (f"/Author ({_esc(author)}) " if author else "")
        info = add(f"<< {fields}/CreationDate (D:20260210000000Z) >>")

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, b in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + b + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offsets:
        out += f"{o:010d} 00000 n \n".encode()
    trailer = f"<< /Size {len(objs) + 1} /Root {catalog} 0 R" + (f" /Info {info} 0 R" if info else "") + " >>"
    out += f"trailer\n{trailer}\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def filler(n: int, topic: str = "identity") -> list[str]:
    return [f"Test line {i} about {topic} telemetry and session tokens for page content." for i in range(n)]
