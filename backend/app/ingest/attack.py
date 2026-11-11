"""MITRE ATT&CK groups and software (public STIX data from github.com/mitre/cti).

The bundle is ~50 MB, so it is streamed to a temporary file and parsed one object at a
time; only intrusion sets (groups) and malware/tools (software) are kept. Nothing is
generated: names, aliases, descriptions and references are MITRE's own, with MITRE's
"(Citation: …)" markers removed from the description.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import tempfile
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from ..db import jdumps, jloads, now_iso, tx
from .fetcher import fetch

log = logging.getLogger(__name__)

MAX_BYTES = 150 * 1024 * 1024
KINDS = {"intrusion-set": "group", "malware": "software", "tool": "software"}
_CITE = re.compile(r"\s*\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)]+)\)")
_ATTACK_ID = re.compile(r"^[GS]\d{4}$")


def iter_objects(path: str, chunk: int = 1 << 16) -> Iterator[dict]:
    """Yield each object in a STIX bundle's "objects" array without loading the whole file."""
    dec = json.JSONDecoder()
    with open(path, encoding="utf-8") as f:
        buf = ""
        while True:  # find the start of the objects array
            data = f.read(chunk)
            if not data:
                return
            buf += data
            i = buf.find('"objects"')
            if i != -1 and (j := buf.find("[", i)) != -1:
                buf = buf[j + 1:]
                break
            buf = buf[-32:]
        while True:
            buf = buf.lstrip(", \n\r\t")
            if buf.startswith("]"):
                return
            try:
                obj, end = dec.raw_decode(buf)
            except json.JSONDecodeError:
                data = f.read(chunk)
                if not data:
                    return
                buf += data
                continue
            yield obj
            buf = buf[end:]


def _https(url: str | None) -> str | None:
    if not url:
        return None
    p = urlsplit(url)
    return url if p.scheme in ("https", "http") and p.netloc else None


def parse(obj: dict) -> dict | None:
    kind = KINDS.get(obj.get("type", ""))
    if not kind or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    refs = obj.get("external_references") or []
    own = next((r for r in refs if r.get("source_name") == "mitre-attack" and _ATTACK_ID.match(r.get("external_id") or "")), None)
    if not own or not _https(own.get("url")):
        return None
    name = (obj.get("name") or "").strip()
    aliases = obj.get("aliases") if kind == "group" else obj.get("x_mitre_aliases")
    aliases = [a.strip() for a in (aliases or []) if a and a.strip() and a.strip().lower() != name.lower()]
    desc = _MDLINK.sub(r"\1", _CITE.sub("", obj.get("description") or "")).strip()
    desc = desc.split("\n\n")[0].strip()
    if len(desc) > 900:
        desc = desc[:900].rsplit(" ", 1)[0] + "…"
    cites = []
    for r in refs:
        url = _https(r.get("url"))
        if r is own or not url or r.get("source_name") == "mitre-attack":
            continue
        cites.append({"source": (r.get("source_name") or "")[:200], "url": url, "description": _CITE.sub("", r.get("description") or "")[:300]})
    return {"stix_id": obj["id"], "kind": kind, "attack_id": own["external_id"], "name": name, "aliases": aliases,
            "description": desc, "url": own["url"], "refs": cites[:60], "modified": obj.get("modified")}


def ingest_attack(conn: sqlite3.Connection, src: dict) -> tuple[int, str | None, str | None]:
    """Download (conditionally, by ETag) and replace the stored groups and software. Returns (count, etag, last_modified)."""
    # The data volume, not /tmp: /tmp is a small in-memory tmpfs in the container. The file is removed afterwards.
    from ..config import get_settings
    work = Path(get_settings().data_dir) / "tmp"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="attack-", suffix=".json", dir=work) as tmp:
        r = fetch(src["url"], etag=src.get("etag"), last_modified=src.get("last_modified"), accept="application/json, text/plain",
                  max_bytes=MAX_BYTES, sink=tmp)
        if r.not_modified:
            return 0, None, None
        tmp.flush()
        rows = [p for o in iter_objects(tmp.name) if (p := parse(o))]
    if len(rows) < 50:  # a truncated or unexpected file must not wipe good data
        raise ValueError(f"only {len(rows)} ATT&CK groups/software found; keeping the previous data")
    now = now_iso()
    with tx(conn):
        conn.execute("DELETE FROM attack_objects")
        conn.executemany(
            """INSERT INTO attack_objects(stix_id, kind, attack_id, name, aliases, description, url, refs, modified, synced_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(x["stix_id"], x["kind"], x["attack_id"], x["name"], jdumps(x["aliases"]), x["description"], x["url"], jdumps(x["refs"]),
              x["modified"], now) for x in rows])
    log.info("MITRE ATT&CK: %d groups and software", len(rows))
    return len(rows), r.headers.get("etag"), r.headers.get("last-modified")


def lookup(conn: sqlite3.Connection, names: list[str], prefer: str) -> dict | None:
    """The ATT&CK entry whose name or alias matches any of ``names`` (exact, case-insensitive)."""
    wanted = {n.strip().lower() for n in names if n and n.strip()}
    if not wanted:
        return None
    ph = ",".join("?" * len(wanted))
    rows = conn.execute(
        f"""SELECT * FROM attack_objects a WHERE lower(a.name) IN ({ph})
              OR EXISTS (SELECT 1 FROM json_each(a.aliases) j WHERE lower(j.value) IN ({ph}))""", [*wanted, *wanted]).fetchall()
    if not rows:
        return None
    primary = names[0].strip().lower()
    best = sorted(rows, key=lambda r: (r["kind"] != prefer, r["name"].lower() != primary))[0]
    d = dict(best)
    d["aliases"] = jloads(d["aliases"])
    d["refs"] = jloads(d["refs"])
    return d
