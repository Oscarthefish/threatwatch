"""Reading view and highlights for extracted report text.

Deterministic and local: works only from the page text already stored, so it can be improved and re-run without
re-reading the PDF. Nothing here interprets the report; it restores layout (paragraphs, headings, lists), sets aside
running headers and figure labels, and collects passages that are worth a look, each with its page number.
Every highlight is the report's own wording. Threat Watch adds only labels (for example "vendor product guidance").
"""
from __future__ import annotations

import re
import statistics
from collections import Counter

ANALYSIS_VERSION = 2

TERMINAL = re.compile(r"[.!?:;”\"')\]]$")
BULLET = re.compile(r"^(?:[+•▪●◦‣■□➢➤✓✔]|[-–—](?=\s)|\(?\d{1,2}[.)](?=\s))\s*")
SYMBOLS = re.compile(r"^[\W_]{1,6}$")
FUNCTION_END = re.compile(r"\b(the|of|and|or|a|an|to|for|in|on|with|as|from|by|at|into|vs\.?)$", re.I)
# "T able" -> "Table", "Key T akeaways" -> "Key Takeaways". Never A or I (words), never after a hyphen ("5500-X and"),
# and never before a common short word ("Plan B is").
KERN = re.compile(r"(?<![\w-])([B-HJ-Z]) (?!(?:and|or|is|the|to|of|in|on|for|with|was|are|as|at|by|it|if|so)\b)(?=[a-z]{2,}\b)")
SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9“\"(])")
STAT = re.compile(
    r"\b\d[\d,.]*\s?%|\b\d[\d,.]*\s?(?:percent|per cent)\b"
    r"|\b(?:over|more than|nearly|almost|roughly|approximately|around|about|up to|at least|fewer than|less than)\s+\$?\d[\d,.]*"
    r"|\b\d+(?:\.\d+)?\s?(?:x|times)\b(?! (?:a|per) )"
    r"|\$\d[\d,.]*\s?(?:million|billion|bn|m)?\b"
    r"|\b\d{1,3}(?:,\d{3})+\b|(?<![-\w])(?!(?:19|20)\d\d\b)\d{4,}(?= [a-z])", re.I)
NOT_STAT = re.compile(r"\bCVE-\d{4}-\s?\d{4,7}\b|\b[A-Z]{1,5}-?\d{3,}[A-Z-]*\b|\b(?:19|20)\d\d\b")  # ids, models, years
PLAYBOOK = re.compile(r"play\s*book|recommendation|mitigat|what (?:defenders|you|security teams) (?:should|can)|defender'?s? (?:guide|actions)|how to defend|best practice", re.I)
TAKEAWAYS = re.compile(r"key\s*take\s*aways|key findings|at a glance|in brief|highlights|key points", re.I)
CHAPTER_LABEL = re.compile(r"^(\d{1,2})\s+([^\d].{1,60})$")

# Product names that mark a passage as the publisher's own product guidance. Only names that are unambiguous.
VENDOR_TERMS: dict[str, list[str]] = {
    "sentinelone": ["Singularity", "Purple AI", "Wayfinder", "Vigilance MDR", "Event Search", "STAR custom rule", "STAR rule", "Storyline"],
    "crowdstrike": ["CrowdStrike Falcon", "Falcon platform", "Falcon OverWatch", "Falcon Complete", "Charlotte AI"],
    "palo alto": ["Cortex XDR", "Cortex XSIAM", "Prisma Cloud", "Unit 42 Retainer"],
    "sophos": ["Sophos MDR", "Intercept X", "Sophos XDR"],
    "microsoft": ["Microsoft Defender", "Defender for Endpoint", "Microsoft Sentinel", "Security Copilot"],
    "red canary": ["Red Canary MDR", "Red Canary Managed"],
    "expel": ["Expel MDR", "Expel Workbench"],
    "mandiant": ["Mandiant Advantage", "Google Security Operations"],
    "cisco": ["Cisco XDR", "Talos Incident Response retainer"],
    "rapid7": ["InsightIDR", "Rapid7 MDR"],
}


def _norm(line: str) -> str:
    """Comparable form of a line: no digits, collapsed spaces, lower case."""
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", line)).strip().lower()


def _clean_lines(text: str) -> list[str]:
    out = []
    for ln in text.split("\n"):
        ln = KERN.sub(r"\1", ln.strip())
        if ln and not SYMBOLS.fullmatch(ln) and not re.fullmatch(r"\d{1,3}", ln):
            out.append(re.sub(r"\s{2,}", " ", ln))
    return out


def layout(pages: list[str]) -> dict:
    """Find running headers, footers and section labels: short lines repeated at the top or bottom of many pages."""
    counts: Counter = Counter()
    originals: dict[str, Counter] = {}
    for t in pages:
        lines = _clean_lines(t)
        edge = lines[:3] + lines[-3:]
        for ln in {l for l in edge if len(l) <= 60 and not re.search(r"[.!?]$", l)}:  # headers are short, not sentences
            k = _norm(ln)
            if len(k) < 3:
                continue
            counts[k] += 1
            originals.setdefault(k, Counter())[re.sub(r"^\d+\s*|\s*\d+$", "", ln).strip()] += 1
    n = max(1, len(pages))
    repeated = {k for k, v in counts.items() if v >= max(3, round(n * 0.05))}
    title_key = next((k for k, v in counts.most_common() if k in repeated and v >= 0.4 * n and len(k.split()) >= 2), None)
    title = originals[title_key].most_common(1)[0][0] if title_key else None
    return {"repeated": sorted(repeated), "running_title": title}


def _vendor_terms(publisher: str | None) -> list[str]:
    if not publisher:
        return []
    low = publisher.lower()
    terms = [t for k, ts in VENDOR_TERMS.items() if k in low for t in ts]
    first = re.split(r"[/(,]", publisher)[0].strip()
    if len(first) >= 4:
        # the publisher's name alone is not product guidance (reports mention themselves constantly)
        terms.append(re.escape(first) + r"['’]s\s+[A-Z]")
        terms.append(re.escape(first) + r"\s+(?:customers?|platform|products?|solutions?|services?|offerings?)\b")
    return terms


HEAD_CONT = re.compile(r"^(?:the|of|and|for|to|in|on|with|an?)\s+[A-Z]")  # "Living Off" / "the Pipeline"
# "Furthermore, ..." or "In addition, ..." start sentences, not headings
DISCOURSE = re.compile(r"^(?:Furthermore|However|Similarly|Additionally|Moreover|Meanwhile|Instead|Therefore|Notably|Importantly"
                       r"|Finally|Overall|Today|Historically|Increasingly|Ultimately|Consequently|Crucially|Separately|Again"
                       r"|In (?:addition|practice|contrast|short|particular|one case|another case)|For (?:example|instance)"
                       r"|As a result|By contrast|At the same time|First|Second|Third),")


def _is_heading_line(ln: str, width: float) -> bool:
    if len(ln) > min(80, width * 0.85) or TERMINAL.search(ln) or not ln[:1].isupper() and not ln[:1].isdigit():
        return False
    if DISCOURSE.match(ln):
        return False
    words = [w for w in re.findall(r"[A-Za-z][\w'’-]*", ln)]
    if not words or len(words) > 12:
        return False
    big = [w for w in words if len(w) >= 4]
    caps = sum(1 for w in big if w[0].isupper())
    return not big or caps / len(big) >= 0.5


def _strong_heading(ln: str) -> bool:
    words = re.findall(r"[A-Za-z][\w'’-]*", ln)
    big = [w for w in words if len(w) >= 4]
    return 2 <= len(words) <= 9 and bool(big) and all(w[0].isupper() for w in big)


def _figure_runs(body: list[str], width: float) -> set[int]:
    """Indexes of lines in runs of four or more short lines: labels from a figure, chart or diagram."""
    short = [len(l) < width * 0.6 and not BULLET.match(l) for l in body]
    out: set[int] = set()
    i = 0
    while i < len(body):
        # the tail of a wrapped sentence is not a figure label
        if not short[i] or (i > 0 and not TERMINAL.search(body[i - 1]) and body[i][:1].islower()):
            i += 1
            continue
        j = i
        while j < len(body) and short[j]:
            # a heading directly followed by a full line of prose ends the run
            if j > i and j + 1 < len(body) and len(body[j + 1]) >= width * 0.8 and _is_heading_line(body[j], width):
                break
            j += 1
        if j - i >= 4:
            out.update(range(i, j))
        i = max(j, i + 1)
    return out


def blocks(text: str, repeated: set[str], vendor_terms: list[str]) -> tuple[list[dict], list[str]]:
    """Turn one page of extracted text into reading blocks. Returns (blocks, labels found in the page furniture)."""
    lines = _clean_lines(text)
    labels: list[str] = []
    body: list[str] = []
    for i, ln in enumerate(lines):
        edge = i < 3 or i >= len(lines) - 3
        caps_label = len(ln) <= 30 and len(ln.split()) <= 3 and ln.isupper() and re.search(r"[A-Z]{3}", ln)
        if edge and (_norm(ln) in repeated or caps_label) and not TAKEAWAYS.search(ln):  # a repeated "Key takeaways" is a heading
            labels.append(ln)
            continue
        body.append(ln)
    lens = [len(l) for l in body if len(l) >= 25]
    width = statistics.median(lens) if lens else 70.0

    figure = _figure_runs(body, width) if len(body) > 6 else set()
    out: list[dict] = []
    cur: dict | None = None
    last_line = ""

    def flush():
        nonlocal cur
        if cur and cur["text"].strip():
            out.append(cur)
        cur = None

    i = 0
    while i < len(body):
        ln = body[i]
        if i in figure:
            if not (cur and cur["type"] == "figure"):
                flush()
                cur = {"type": "figure", "text": ln}
            else:
                cur["text"] += " · " + ln
            last_line = "."
            i += 1
            continue
        if cur and cur["type"] == "figure":
            flush()
        nxt = body[i + 1] if i + 1 < len(body) else ""
        m = BULLET.match(ln)
        if m and len(ln) > m.end():
            flush()
            cur = {"type": "li", "text": ln[m.end():].strip()}
            last_line = ln
            i += 1
            continue
        para_ended = cur is None or bool(TERMINAL.search(last_line)) and (len(last_line) < width * 0.92 or _strong_heading(ln))
        if para_ended and _is_heading_line(ln, width):
            # a heading may wrap onto a second line; the line after it must start a sentence
            head, j = ln, i + 1
            if nxt and HEAD_CONT.match(nxt) and len(nxt) < width * 0.6 and not TERMINAL.search(nxt):
                head, j = f"{ln} {nxt}", i + 2
            elif nxt and _is_heading_line(nxt, width) and not TAKEAWAYS.search(nxt) and not PLAYBOOK.search(nxt) and (
                    FUNCTION_END.search(ln) or len(nxt.split()) == 1 or (len(ln.split()) >= 2 and len(nxt.split()) <= 3)):
                head, j = f"{ln} {nxt}", i + 2
            after = body[j] if j < len(body) else ""
            if not after or after[:1].isupper() or after[:1].isdigit() or BULLET.match(after) or _is_heading_line(after, width):
                flush()
                out.append({"type": "h", "text": head})
                last_line = "."
                i = j
                continue
        if cur is not None and cur["type"] == "li":  # a wrapped bullet continues in lower case
            continues = ln[:1].islower() or last_line.endswith(("-", ","))
        else:
            continues = cur is not None and cur["type"] == "p" and (
                not TERMINAL.search(last_line) or ln[:1].islower() or len(last_line) >= width * 0.92)
        if continues:
            sep = "" if cur["text"].endswith("-") and ln[:1].islower() else " "
            cur["text"] += sep + ln
        else:
            flush()
            cur = {"type": "p", "text": ln}
        last_line = ln
        i += 1
    flush()

    # Runs of short fragments are labels from a figure or diagram, not prose.
    merged: list[dict] = []
    run: list[dict] = []

    def end_run():
        if len(run) >= 4:
            merged.append({"type": "figure", "text": " · ".join(b["text"] for b in run)})
        else:
            merged.extend(run)
        run.clear()

    for b in out:
        if b["type"] in ("p", "h") and len(b["text"]) < 42 and not TERMINAL.search(b["text"]):
            run.append(b)
        else:
            end_run()
            merged.append(b)
    end_run()

    if vendor_terms:
        parts = [t if "\\" in t else re.escape(t) + r"(?![\w-])" for t in vendor_terms]
        pat = re.compile(r"(?<![\w-])(?:" + "|".join(parts) + r")")
        for b in merged:
            if b["type"] in ("p", "li") and pat.search(b["text"]):
                b["vendor"] = True
    return merged, labels


def _chapters(page_labels: list[list[str]], page_blocks: list[list[dict]]) -> list[dict]:
    named: dict[str, tuple[str, str]] = {}
    for labels in page_labels:
        for lab in labels:
            m = CHAPTER_LABEL.match(lab)
            if m:
                name = m.group(2).strip()
                named.setdefault(_norm(lab), (m.group(1).zfill(2), name.title() if name.isupper() else name))
    out: list[dict] = []
    for pno, labels in enumerate(page_labels, 1):
        # a numbered label ("06 MAINTENANCE") outranks a bare word that happens to match another chapter
        hit = next((named[_norm(l)] for l in labels if CHAPTER_LABEL.match(l) and _norm(l) in named), None) or next(
            (named[_norm(l)] for l in labels if _norm(l) in named), None)
        if not hit:
            continue
        num, name = hit
        same = next((c for c in out if c["number"] == num), None)
        if same and same is out[-1]:  # unlabelled pages inside a chapter do not split it
            same["end"] = pno
        else:
            first_h = next((b["text"] for b in page_blocks[pno - 1] if b["type"] == "h"), None)
            out.append({"number": num, "title": name, "subtitle": first_h if first_h and _norm(first_h) != _norm(name) else None,
                        "start": pno, "end": pno})
    # a chapter needs at least two labelled pages to count
    return [c for c in out if c["end"] > c["start"]]


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in SENTENCE.split(text) if s.strip()]


def analyse(conn, pages: list[str], publisher: str | None) -> dict:
    """Reading blocks for every page plus report-level highlights. `conn` is used only to validate ATT&CK IDs and
    look up CVEs already known to Threat Watch."""
    from ..intel import entities

    lay = layout(pages)
    repeated = set(lay["repeated"])
    vterms = _vendor_terms(publisher or (lay["running_title"] or "").split(" ")[0] or None)
    page_blocks: list[list[dict]] = []
    page_labels: list[list[str]] = []
    for t in pages:
        b, labels = blocks(t, repeated, vterms)
        page_blocks.append(b)
        page_labels.append(labels)
    chapters = _chapters(page_labels, page_blocks)

    def chapter_of(p: int) -> str | None:
        for c in chapters:
            if c["start"] <= p <= c["end"]:
                return f"{c['number']} {c['title']}"
        return None

    takeaways, recs, vendor, stats = [], [], [], []
    seen_stats: set[str] = set()
    ent: dict[tuple[str, str], dict] = {}
    for pno, (bl, labels) in enumerate(zip(page_blocks, page_labels), 1):
        playbook_page = any(PLAYBOOK.search(re.sub(r"\s", "", l)) or PLAYBOOK.search(l) for l in labels) or any(
            b["type"] == "h" and PLAYBOOK.search(b["text"]) for b in bl)
        heading = None
        in_takeaways = False
        for k, b in enumerate(bl):
            if b["type"] == "h":
                heading = b["text"]
                in_takeaways = bool(TAKEAWAYS.search(b["text"]))
                continue
            if b["type"] == "figure":
                continue
            if b.get("vendor"):
                vendor.append({"page": pno, "text": b["text"]})
                continue
            if in_takeaways and b["type"] == "li":
                takeaways.append({"page": pno, "chapter": chapter_of(pno), "text": b["text"]})
                continue
            if playbook_page and heading and b["type"] == "p" and k > 0 and bl[k - 1]["type"] == "h" and not PLAYBOOK.search(heading):
                recs.append({"page": pno, "chapter": chapter_of(pno), "title": heading, "text": b["text"]})
                continue
            if playbook_page and b["type"] == "li":
                recs.append({"page": pno, "chapter": chapter_of(pno), "title": None, "text": b["text"]})
                continue
            for s in _sentences(b["text"]):
                if 40 <= len(s) <= 420 and STAT.search(NOT_STAT.sub(" ", s)) and s not in seen_stats:
                    seen_stats.add(s)
                    stats.append({"page": pno, "chapter": chapter_of(pno), "text": s})
        text = "\n".join(b["text"] for b in bl if not b.get("vendor"))
        for e in entities.extract("", text):
            if e.type not in ("actor", "ransomware", "malware", "vendor", "product", "cve", "technique"):
                continue
            key = (e.type, e.normalized)
            rec = ent.setdefault(key, {"type": e.type, "value": e.value, "pages": []})
            if pno not in rec["pages"]:
                rec["pages"].append(pno)

    def group(t):
        return sorted(({"value": v["value"], "pages": v["pages"]} for (tt, _), v in ent.items() if tt == t),
                      key=lambda x: (-len(x["pages"]), x["value"].lower()))

    cves = group("cve")
    known = {}
    if cves:
        q = ",".join("?" * len(cves))
        for r in conn.execute(f"SELECT cve_id, cvss_score, kev FROM vulnerabilities WHERE cve_id IN ({q})", [c["value"].upper() for c in cves]):
            known[r[0]] = {"cvss": r[1], "kev": bool(r[2])}
    for c in cves:
        c["value"] = c["value"].upper()
        c["known"] = known.get(c["value"])

    techniques = _techniques(conn, page_blocks)
    return {
        "version": ANALYSIS_VERSION,
        "running_title": lay["running_title"],
        "chapters": chapters,
        "pages": [{"blocks": b, "labels": l} for b, l in zip(page_blocks, page_labels)],
        "highlights": {
            "takeaways": takeaways, "recommendations": recs, "vendor_guidance": vendor, "statistics": stats,
            "actors": group("actor"), "malware": group("malware") + group("ransomware"),
            "technologies": group("product") + group("vendor"), "cves": cves, "techniques": techniques,
        },
    }


def _techniques(conn, page_blocks: list[list[dict]]) -> list[dict]:
    """ATT&CK techniques: IDs cited in the text (validated against the local ATT&CK data, revoked IDs resolved) and
    technique names that appear verbatim. Names are a Threat Watch match, not the publisher's mapping."""
    rows = conn.execute("SELECT attack_id, name, tactics FROM attack_techniques").fetchall() if _has(conn, "attack_techniques") else []
    if not rows:
        return []
    by_id = {r[0]: r[1] for r in rows}
    revoked = dict(conn.execute("SELECT old_id, new_id FROM attack_revoked").fetchall()) if _has(conn, "attack_revoked") else {}
    name_count = Counter(r[1].lower() for r in rows)
    generic = {"multi-factor authentication", "cloud services", "web services", "code signing", "software", "rootkit",
               "network share discovery", "password managers", "conditional access policies", "hybrid identity"}
    names = []
    for tid, name, tactics in rows:
        if name_count[name.lower()] > 1 or name.lower() in generic:  # ambiguous, or usually the defence not the attack
            continue
        tac = (tactics or "")
        if ("reconnaissance" in tac or "resource-development" in tac) and "initial-access" not in tac:
            continue
        if len(name) >= 8 and (" " in name or name[0].isupper()):
            names.append((tid, name, re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.I if " " in name else 0)))
    found: dict[str, dict] = {}
    for pno, bl in enumerate(page_blocks, 1):
        text = "\n".join(b["text"] for b in bl if not b.get("vendor"))
        for m in re.finditer(r"\b(T1\d{3}(?:\.\d{3})?)\b", text):
            tid = revoked.get(m.group(1), m.group(1))
            if tid in by_id:
                rec = found.setdefault(tid, {"id": tid, "name": by_id[tid], "basis": "cited", "pages": []})
                rec["basis"] = "cited"
                if pno not in rec["pages"]:
                    rec["pages"].append(pno)
        for tid, name, pat in names:
            if pat.search(text):
                rec = found.setdefault(tid, {"id": tid, "name": name, "basis": "named", "pages": []})
                if pno not in rec["pages"]:
                    rec["pages"].append(pno)
    return sorted(found.values(), key=lambda r: (r["basis"] != "cited", -len(r["pages"]), r["id"]))


def _has(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
