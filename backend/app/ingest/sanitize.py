"""Turn untrusted feed HTML into bounded plain text.

Feed content is never rendered as HTML in the UI. We strip all markup with
nh3 (ammonia), unescape entities, remove control characters and collapse
whitespace. Length is capped to bound storage and AI prompt size.
"""
from __future__ import annotations

import html
import re

import nh3

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_WS = re.compile(r"[ \t\r\f\v]+")
_NL = re.compile(r"\n{3,}")
_BLOCK = re.compile(r"(?i)<\s*(br|/p|/div|/li|/h[1-6]|/tr|/pre|/blockquote)\b[^>]*>")
_ENTITY = re.compile(r"&(#\d{1,6}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});")
_DROP = re.compile(r"(?is)<\s*(script|style|noscript|iframe|object|svg)\b.*?<\s*/\s*\1\s*>")


def html_to_text(raw: str | None, max_len: int = 20000) -> str:
    if not raw:
        return ""
    s = _DROP.sub(" ", raw)
    s = _BLOCK.sub("\n", s)
    s = nh3.clean(s, tags=set(), attributes={}, strip_comments=True)
    for _ in range(3):  # some feeds escape entities two or three times (&amp;amp;quot;)
        s = html.unescape(s)
        if not _ENTITY.search(s):
            break
    s = _CTRL.sub("", s)
    s = "\n".join(_WS.sub(" ", line).strip() for line in s.split("\n"))
    s = _NL.sub("\n\n", s).strip()
    if len(s) > max_len:
        s = s[:max_len].rsplit(" ", 1)[0] + " …"
    return s


def clean_title(raw: str | None) -> str:
    t = html_to_text(raw, max_len=500).replace("\n", " ")
    return re.sub(r"\s+", " ", t).strip()
