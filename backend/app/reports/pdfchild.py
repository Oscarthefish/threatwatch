"""Extract text from one PDF, inside a resource-limited child process.

Run as ``python -I pdfchild.py <path> <max_pages> <max_chars_per_page> <memory_mb>`` by ``app.reports.process``.
It imports nothing from the app, receives an empty environment (so no API keys), may not create files,
and is capped on memory, CPU time and open files before the PDF is opened. It prints one JSON object
on stdout. Document content is treated as data only: nothing in it is executed or followed, and
JavaScript, forms, attachments and links in the PDF are ignored.
"""
from __future__ import annotations

import json
import re
import resource
import sys
import unicodedata

CPU_SECONDS = 150


def limit(mem_mb: int) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
    except (ValueError, OSError):  # not supported on macOS; the container memory limit still applies
        pass


CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")


def clean(text: str, cap: int) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = CONTROL.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:cap]


def meta_str(v, cap: int = 300) -> str | None:
    if v is None:
        return None
    s = clean(str(v), cap)
    return s or None


def outline(reader, cap: int = 400) -> list[dict]:
    out: list[dict] = []

    def walk(items, level: int) -> None:
        for it in items:
            if len(out) >= cap:
                return
            if isinstance(it, list):
                walk(it, level + 1)
                continue
            try:
                title = meta_str(getattr(it, "title", None), 200)
                page = reader.get_destination_page_number(it)
            except Exception:
                continue
            if title and page is not None and page >= 0:
                out.append({"title": title, "page": page + 1, "level": min(level, 4)})

    try:
        walk(reader.outline, 1)
    except Exception:
        return []
    return out


def main() -> None:
    path, max_pages, max_chars, mem_mb = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    limit(mem_mb)
    from pypdf import PdfReader
    from pypdf.errors import DependencyError, FileNotDecryptedError, PdfReadError

    try:
        reader = PdfReader(path, strict=False)
        if reader.is_encrypted:
            try:
                ok = reader.decrypt("")
            except (DependencyError, NotImplementedError):
                ok = 0
            if not ok:
                print(json.dumps({"error": "encrypted"}))
                return
        total = len(reader.pages)
    except FileNotDecryptedError:
        print(json.dumps({"error": "encrypted"}))
        return
    except (PdfReadError, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError) as e:
        print(json.dumps({"error": "unreadable", "detail": type(e).__name__}))
        return

    meta = {}
    try:
        m = reader.metadata or {}
        for k, name in (("/Title", "title"), ("/Author", "author"), ("/Subject", "subject"), ("/Creator", "creator"),
                        ("/Producer", "producer"), ("/CreationDate", "created"), ("/ModDate", "modified")):
            v = meta_str(m.get(k))
            if v:
                meta[name] = v
    except Exception:
        pass
    try:
        labels = list(reader.page_labels)
    except Exception:
        labels = []

    pages = []
    failed = 0
    for i in range(min(total, max_pages)):
        try:
            t = clean(reader.pages[i].extract_text() or "", max_chars)
        except MemoryError:
            raise
        except Exception:
            t, failed = "", failed + 1
        lab = labels[i] if i < len(labels) else None
        pages.append({"n": i + 1, "label": lab if lab and lab != str(i + 1) else None, "text": t})
    print(json.dumps({"pages": pages, "total_pages": total, "truncated": total > max_pages, "page_errors": failed,
                      "meta": meta, "outline": outline(reader)}))


if __name__ == "__main__":
    try:
        main()
    except MemoryError:
        sys.stdout.write(json.dumps({"error": "limits"}))
