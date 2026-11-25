"""MITRE ATT&CK Enterprise (public STIX data from github.com/mitre-attack/attack-stix-data).

The bundle is ~55 MB, so it is streamed to a temporary file and parsed one object at a
time. Kept: groups and software (attack_objects), tactics, techniques, mitigations,
detection strategies with their analytics, the relationships between them, and the
release version. Revoked and deprecated objects are dropped (revoked technique IDs are
mapped to their replacement). Nothing is generated: names, descriptions and references
are MITRE's own, with MITRE's "(Citation: …)" markers removed.
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

from ..db import jdumps, jloads, now_iso, set_setting, tx
from .fetcher import fetch

log = logging.getLogger(__name__)

MAX_BYTES = 150 * 1024 * 1024
KINDS = {"intrusion-set": "group", "malware": "software", "tool": "software"}
_CITE = re.compile(r"\s*\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)]+)\)")
_ATTACK_ID = re.compile(r"^[GS]\d{4}$")
_TECH_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_OTHER_ID = {"x-mitre-tactic": re.compile(r"^TA\d{4}$"), "course-of-action": re.compile(r"^M\d{4}$"),
             "x-mitre-detection-strategy": re.compile(r"^DET\d{4}$"), "x-mitre-analytic": re.compile(r"^AN\d{4}$")}


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


def _own_id(obj: dict, pattern: re.Pattern) -> dict | None:
    return next((r for r in obj.get("external_references") or []
                 if r.get("source_name") == "mitre-attack" and pattern.match(r.get("external_id") or "")), None)


def _clean(text: str | None, limit: int, paragraphs: int = 1) -> str:
    t = _MDLINK.sub(r"\1", _CITE.sub("", text or "")).replace("<code>", "").replace("</code>", "").strip()
    t = "\n\n".join(p.strip() for p in t.split("\n\n")[:paragraphs] if p.strip())
    return t if len(t) <= limit else t[:limit].rsplit(" ", 1)[0] + "…"


class Collector:
    """Accumulates the parts of the bundle Threat Watch keeps, then resolves relationships by ATT&CK ID."""

    def __init__(self) -> None:
        self.version: str | None = None
        self.groups: list[dict] = []
        self.ids: dict[str, str] = {}          # stix id -> ATT&CK id (live objects only)
        self.tactics: dict[str, dict] = {}     # stix id -> tactic
        self.tactic_order: list[str] = []
        self.techniques: list[dict] = []
        self.mitigations: list[dict] = []
        self.detections: list[dict] = []
        self.analytics: dict[str, dict] = {}   # stix id -> analytic
        self.components: dict[str, str] = {}   # data component stix id -> name
        self.rels: list[tuple[str, str, str]] = []
        self.revoked: dict[str, str] = {}      # revoked technique stix id -> its ATT&CK id

    def add(self, o: dict) -> None:
        t = o.get("type", "")
        if t == "x-mitre-collection":
            self.version = o.get("x_mitre_version")
            return
        if t == "relationship":
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                return
            if o.get("relationship_type") in ("uses", "mitigates", "detects", "subtechnique-of", "revoked-by"):
                self.rels.append((o["source_ref"], o["relationship_type"], o["target_ref"]))
            return
        if t == "x-mitre-matrix":
            self.tactic_order = list(o.get("tactic_refs") or [])
            return
        if t == "x-mitre-data-component":
            self.components[o["id"]] = o.get("name") or ""
            return
        if t == "attack-pattern" and o.get("revoked"):
            own = _own_id(o, _TECH_ID)
            if own:
                self.revoked[o["id"]] = own["external_id"]
            return
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            return
        if t in KINDS:
            g = parse(o)
            if g:
                self.groups.append(g)
                self.ids[o["id"]] = g["attack_id"]
            return
        if t == "attack-pattern":
            own = _own_id(o, _TECH_ID)
            if not own or not _https(own.get("url")):
                return
            phases = [p["phase_name"] for p in o.get("kill_chain_phases") or [] if p.get("kill_chain_name") == "mitre-attack"]
            tid = own["external_id"]
            self.techniques.append({"attack_id": tid, "stix_id": o["id"], "name": (o.get("name") or "").strip(),
                                    "parent_id": tid.split(".")[0] if "." in tid else None, "tactics": phases,
                                    "platforms": o.get("x_mitre_platforms") or [], "description": _clean(o.get("description"), 1500, 2),
                                    "url": own["url"], "modified": o.get("modified")})
            self.ids[o["id"]] = tid
            return
        pat = _OTHER_ID.get(t)
        own = _own_id(o, pat) if pat else None
        if not own:
            return
        aid, url = own["external_id"], _https(own.get("url")) or ""
        if t == "x-mitre-tactic":
            self.tactics[o["id"]] = {"attack_id": aid, "shortname": o.get("x_mitre_shortname") or "", "name": o.get("name") or "", "url": url}
        elif t == "course-of-action":
            self.mitigations.append({"attack_id": aid, "name": o.get("name") or "", "description": _clean(o.get("description"), 900), "url": url})
            self.ids[o["id"]] = aid
        elif t == "x-mitre-detection-strategy":
            self.detections.append({"attack_id": aid, "name": o.get("name") or "", "url": url, "refs": list(o.get("x_mitre_analytic_refs") or [])})
            self.ids[o["id"]] = aid
        elif t == "x-mitre-analytic":
            self.analytics[o["id"]] = {"id": aid, "platforms": o.get("x_mitre_platforms") or [], "description": _clean(o.get("description"), 700),
                                       "log_sources": [{"name": (ls.get("name") or "")[:80], "channel": (ls.get("channel") or "")[:200]}
                                                       for ls in (o.get("x_mitre_log_source_references") or [])[:8]]}

    def links(self) -> list[tuple[str, str, str]]:
        out = set()
        for src, rel, dst in self.rels:
            a, b = self.ids.get(src), self.ids.get(dst)
            if rel in ("uses", "mitigates", "detects") and a and b and b.startswith("T"):
                out.add((a, rel, b))
        return sorted(out)

    def revoked_map(self) -> dict[str, str]:
        return {self.revoked[s]: self.ids[d] for s, rel, d in self.rels
                if rel == "revoked-by" and s in self.revoked and d in self.ids and self.ids[d].startswith("T")}

    def tactic_rows(self) -> list[dict]:
        order = [self.tactics[r] for r in self.tactic_order if r in self.tactics] or sorted(self.tactics.values(), key=lambda x: x["attack_id"])
        return [{**t, "ord": i} for i, t in enumerate(order)]


def ingest_attack(conn: sqlite3.Connection, src: dict) -> tuple[int, str | None, str | None]:
    """Download (conditionally, by ETag) and replace the stored ATT&CK data. Returns (count, etag, last_modified)."""
    # The data volume, not /tmp: /tmp is a small in-memory tmpfs in the container. The file is removed afterwards.
    from ..config import get_settings
    work = Path(get_settings().data_dir) / "tmp"
    work.mkdir(parents=True, exist_ok=True)
    have_techniques = conn.execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0] > 0
    with tempfile.NamedTemporaryFile(prefix="attack-", suffix=".json", dir=work) as tmp:
        r = fetch(src["url"], etag=src.get("etag") if have_techniques else None,
                  last_modified=src.get("last_modified") if have_techniques else None, accept="application/json, text/plain",
                  max_bytes=MAX_BYTES, sink=tmp)
        if r.not_modified:
            return 0, None, None
        tmp.flush()
        col = Collector()
        for o in iter_objects(tmp.name):
            col.add(o)
    store(conn, col)
    return len(col.groups) + len(col.techniques), r.headers.get("etag"), r.headers.get("last-modified")


def store(conn: sqlite3.Connection, col: Collector) -> None:
    rows = col.groups
    if len(rows) < 50 or len(col.techniques) < 300 or len(col.tactics) < 10:  # truncated or unexpected file: keep good data
        raise ValueError(f"only {len(rows)} groups/software and {len(col.techniques)} techniques found; keeping the previous data")
    now = now_iso()
    links = col.links()
    with tx(conn):
        conn.execute("DELETE FROM attack_objects")
        conn.executemany(
            """INSERT INTO attack_objects(stix_id, kind, attack_id, name, aliases, description, url, refs, modified, synced_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(x["stix_id"], x["kind"], x["attack_id"], x["name"], jdumps(x["aliases"]), x["description"], x["url"], jdumps(x["refs"]),
              x["modified"], now) for x in rows])
        for t in ("attack_tactics", "attack_techniques", "attack_mitigations", "attack_detections", "attack_links", "attack_revoked"):
            conn.execute(f"DELETE FROM {t}")
        conn.executemany("INSERT INTO attack_tactics(attack_id, shortname, name, ord, url) VALUES(?,?,?,?,?)",
                         [(t["attack_id"], t["shortname"], t["name"], t["ord"], t["url"]) for t in col.tactic_rows()])
        conn.executemany(
            """INSERT OR REPLACE INTO attack_techniques(attack_id, stix_id, name, parent_id, tactics, platforms, description, url, modified)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            [(t["attack_id"], t["stix_id"], t["name"], t["parent_id"], jdumps(t["tactics"]), jdumps(t["platforms"]), t["description"],
              t["url"], t["modified"]) for t in col.techniques])
        conn.executemany("INSERT OR REPLACE INTO attack_mitigations(attack_id, name, description, url) VALUES(?,?,?,?)",
                         [(m["attack_id"], m["name"], m["description"], m["url"]) for m in col.mitigations])
        conn.executemany(
            "INSERT OR REPLACE INTO attack_detections(attack_id, name, url, analytics) VALUES(?,?,?,?)",
            [(d["attack_id"], d["name"], d["url"], jdumps([col.analytics[a] for a in d["refs"] if a in col.analytics]))
             for d in col.detections])
        conn.executemany("INSERT OR IGNORE INTO attack_links(src, rel, dst) VALUES(?,?,?)", links)
        conn.executemany("INSERT OR REPLACE INTO attack_revoked(old_id, new_id) VALUES(?,?)", list(col.revoked_map().items()))
        set_setting(conn, "attack_version", col.version)
        set_setting(conn, "attack_synced_at", now)
    log.info("MITRE ATT&CK %s: %d groups/software, %d techniques, %d mitigations, %d detection strategies, %d links",
             col.version, len(rows), len(col.techniques), len(col.mitigations), len(col.detections), len(links))


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
