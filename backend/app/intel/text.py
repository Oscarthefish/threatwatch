"""Display helpers for publisher text.

These never rewrite what a publisher said. They decode leftover HTML entities,
trim excerpts at word or sentence boundaries, find the passages that mention a
term (used to show *why* a report matched), and flag dates that disagree.
"""
from __future__ import annotations

import html
import re
from datetime import date, datetime, timedelta, timezone

_ENTITY = re.compile(r"&(#\d{1,6}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});")
# Publisher truncation markers at the end of feed summaries: "[…]", "...", "Read more"
_TRAIL = re.compile(r"\s*(\[\s*(?:…|\.\.\.)\s*\]|\.\.\.|…|\(more\.*\)|read more\.?|continue reading\.?|the post .{0,120} appeared first on .{0,80}\.?)\s*$", re.I)
_SENT = re.compile(r"(?<=[.!?])[\"'”’)]?\s+(?=[\"'“(]?[A-Z0-9])")


def unescape_all(s: str | None) -> str:
    """Decode HTML entities, including feeds that escape them two or three times."""
    s = s or ""
    for _ in range(3):
        if not _ENTITY.search(s):
            break
        s = html.unescape(s)
    return s


def excerpt(text: str | None, limit: int = 280) -> str:
    """A readable excerpt: whole words, preferring a sentence end, with one ellipsis when shortened."""
    t = re.sub(r"\s+", " ", unescape_all(text)).strip()
    stripped = _TRAIL.sub("", t)
    cut_by_publisher = stripped != t
    t = stripped.rstrip(" ,;:-–")
    if cut_by_publisher and not t.endswith((".", "!", "?")):
        # the publisher cut mid-sentence ("... OpenSSH is t"): end at the last full sentence when there is one
        end = max(t.rfind(". "), t.rfind("? "), t.rfind("! "))
        t = t[: end + 1] if end >= len(t) * 0.4 else t + "…"
    if len(t) <= limit:
        return t
    window = t[:limit]
    end = max(window.rfind(". "), window.rfind("? "), window.rfind("! "))
    if end >= limit * 0.6:
        return window[: end + 1]
    return window.rsplit(" ", 1)[0].rstrip(" ,;:-–(") + "…"


def term_re(term: str) -> re.Pattern:
    return re.compile(rf"(?<![\w-]){re.escape(term.strip())}(?![\w-])", re.I)


def sentences(text: str) -> list[str]:
    out: list[str] = []
    for para in unescape_all(text).split("\n"):
        para = re.sub(r"\s+", " ", para).strip()
        if para:
            out.extend(s.strip() for s in _SENT.split(para) if s.strip())
    return out


def _window(s: str, start: int, end: int, width: int) -> str:
    if len(s) <= width:
        return s
    half = max(0, (width - (end - start)) // 2)
    a, b = max(0, start - half), min(len(s), end + half)
    if a > 0 and (sp := s.find(" ", a, start)) != -1:
        a = sp + 1
    if b < len(s) and (sp := s.rfind(" ", end, b)) != -1:
        b = sp
    return ("…" if a > 0 else "") + s[a:b].strip() + ("…" if b < len(s) else "")


def passages(text: str, terms: list[str], limit: int = 2, width: int = 260) -> list[dict]:
    """Sentences that mention any of ``terms``, trimmed around the first match."""
    pats = [(t, term_re(t)) for t in dict.fromkeys(x for x in terms if x and x.strip())]
    out: list[dict] = []
    for s in sentences(text):
        hits = [(t, m) for t, p in pats if (m := p.search(s))]
        if not hits:
            continue
        first = min(hits, key=lambda h: h[1].start())[1]
        out.append({"text": _window(s, first.start(), first.end(), width), "terms": [t for t, _ in hits]})
        if len(out) >= limit:
            break
    return out


def near_text(text: str, terms: list[str], radius: int = 0) -> str:
    """The sentences mentioning ``terms`` (plus ``radius`` either side): the part of a report that is about the subject."""
    ss = sentences(text)
    pats = [term_re(t) for t in terms if t and t.strip()]
    keep: set[int] = set()
    for i, s in enumerate(ss):
        if any(p.search(s) for p in pats):
            keep.update(range(i - radius, i + radius + 1))
    return " ".join(ss[i] for i in sorted(keep) if 0 <= i < len(ss))


# ------------------------------------------------------------------ dates
_MONTHS = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july", "august",
                                         "september", "october", "november", "december"], 1)}
_MON = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_MONTH_YEAR = re.compile(rf"\b{_MON}\.?\s+(?:(\d{{1,2}})(?:st|nd|rd|th)?,?\s+)?(20\d\d)\b", re.I)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _local(d: datetime) -> datetime:
    try:
        from zoneinfo import ZoneInfo

        from ..config import get_settings
        return d.astimezone(ZoneInfo(get_settings().timezone))
    except Exception:  # timezone data unavailable: fall back to UTC
        return d


def _fmt(d: date) -> str:
    return f"{d.day} {d.strftime('%b')} {d.year}"


def date_notes(title: str, published_at: str | None, retrieved_at: str | None, now: datetime | None = None) -> list[str]:
    """Plain-language notes when dates disagree. The title itself is never changed."""
    pub, ret = _parse(published_at), _parse(retrieved_at)
    now = now or datetime.now(timezone.utc)
    pub_local = _local(pub).date() if pub else None
    notes: list[str] = []
    if pub and pub > now + timedelta(hours=1):
        notes.append(f"Dated {_fmt(_local(pub).date())}, which is in the future.")
    elif pub and ret and pub > ret + timedelta(hours=1):
        notes.append(f"The publisher's date ({_fmt(_local(pub).date())}) is later than when it was collected.")
    if pub:
        for m in _MONTH_YEAR.finditer(title or ""):
            month = next(v for k, v in _MONTHS.items() if k.startswith(m.group(1).lower()[:3]))
            year, day = int(m.group(3)), m.group(2)
            try:
                named = date(year, month, int(day) if day else 1)
            except ValueError:
                continue
            gap = (named - pub_local).days
            if (day and abs(gap) > 2) or (not day and gap > 31):
                notes.append(f"The title says {m.group(0).strip()}, but it was published {_fmt(pub_local)}. Check the source for the correct date.")
                break
    return notes
