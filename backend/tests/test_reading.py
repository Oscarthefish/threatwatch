"""MITRE ATT&CK sync and further-reading links (synthetic STIX data, no network)."""
import json

from app.ingest import attack
from app.intel import reading


def _ref(kind, aid, path):
    return [{"source_name": "mitre-attack", "external_id": aid, "url": f"https://attack.mitre.org/{path}/{aid}"}]


def _bundle(n_extra=60, n_tech=320):
    tactics = [{"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{i}", "name": f"Tactic {i}", "x_mitre_shortname": f"tactic-{i}",
                "external_references": _ref("t", f"TA{i:04d}", "tactics")} for i in range(12)]
    techs = [{"type": "attack-pattern", "id": f"attack-pattern--{i}", "name": f"Technique {i}",
              "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": f"tactic-{i % 12}"}],
              "x_mitre_platforms": ["Windows"], "description": "Does a thing.(Citation: X) <code>cmd.exe</code>",
              "external_references": _ref("x", f"T{1000 + i}", "techniques")} for i in range(n_tech)]
    objs = [{"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.1"},
            {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": [t["id"] for t in reversed(tactics)]},
            *tactics, *techs,
            {"type": "attack-pattern", "id": "attack-pattern--sub", "name": "Sub", "x_mitre_is_subtechnique": True,
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "tactic-1"}],
             "external_references": _ref("x", "T1000.001", "techniques")},
            {"type": "attack-pattern", "id": "attack-pattern--gone", "name": "Old", "revoked": True,
             "external_references": _ref("x", "T0999", "techniques")},
            {"type": "attack-pattern", "id": "attack-pattern--dep", "name": "Deprecated", "x_mitre_deprecated": True,
             "external_references": _ref("x", "T0998", "techniques")},
            {"type": "course-of-action", "id": "course-of-action--1", "name": "Multi-factor Authentication",
             "description": "Use MFA.", "external_references": _ref("m", "M1032", "mitigations")},
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1", "x_mitre_platforms": ["Windows"], "description": "Watch logons.",
             "x_mitre_log_source_references": [{"name": "WinEventLog:Security", "channel": "EventCode=4624"}],
             "external_references": _ref("a", "AN0001", "detectionstrategies")},
            {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1", "name": "Detect odd logons",
             "x_mitre_analytic_refs": ["x-mitre-analytic--1"], "external_references": _ref("d", "DET0001", "detectionstrategies")},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--0"},
            {"type": "relationship", "id": "relationship--2", "relationship_type": "mitigates", "source_ref": "course-of-action--1", "target_ref": "attack-pattern--0"},
            {"type": "relationship", "id": "relationship--3", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--1", "target_ref": "attack-pattern--0"},
            {"type": "relationship", "id": "relationship--4", "relationship_type": "revoked-by", "source_ref": "attack-pattern--gone", "target_ref": "attack-pattern--1"},
            {"type": "relationship", "id": "relationship--5", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--dep"},
            {"type": "relationship", "id": "relationship--6", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1", "revoked": True},
            ]
    objs += [
        {"type": "campaign", "id": "campaign--1", "name": "Ignored"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Example Group", "aliases": ["Example Group", "Example Bear"],
         "description": "Example Group is a test group.(Citation: Vendor 2099) It uses [Tool](https://attack.mitre.org/software/S9999).\n\nSecond paragraph.",
         "modified": "2099-01-01T00:00:00Z",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G9999", "url": "https://attack.mitre.org/groups/G9999"},
                                 {"source_name": "Vendor 2099", "url": "https://research.example.com/report", "description": "Vendor. (2099). Report."},
                                 {"source_name": "Bad", "url": "javascript:alert(1)"}]},
        {"type": "malware", "id": "malware--old", "name": "Old Tool", "x_mitre_deprecated": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "S9998", "url": "https://attack.mitre.org/software/S9998"}]},
    ]
    objs += [{"type": "tool", "id": f"tool--{i}", "name": f"Filler {i}", "x_mitre_aliases": [f"Filler {i}"],
              "external_references": [{"source_name": "mitre-attack", "external_id": f"S{i:04d}", "url": f"https://attack.mitre.org/software/S{i:04d}"}]}
             for i in range(n_extra)]
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": objs}, indent=4).encode()


def _ingest(conn, monkeypatch, **kw):
    def fake_fetch(url, *, sink=None, **_):
        sink.write(_bundle(**kw))
        from app.ingest.fetcher import FetchResult
        return FetchResult(url=url, status=200, headers={"etag": '"abc"'})
    monkeypatch.setattr(attack, "fetch", fake_fetch)
    return attack.ingest_attack(conn, {"url": "https://raw.githubusercontent.com/x.json", "etag": None, "last_modified": None})


def test_stream_parser_and_cleaning(tmp_path):
    p = tmp_path / "b.json"
    p.write_bytes(_bundle())
    objs = list(attack.iter_objects(str(p), chunk=257))   # tiny chunks: objects span many reads
    assert len([o for o in objs if o["type"] in ("intrusion-set", "malware", "tool")]) == 62
    rows = [r for o in objs if (r := attack.parse(o))]
    g = next(r for r in rows if r["attack_id"] == "G9999")
    assert g["description"] == "Example Group is a test group. It uses Tool."      # citations and links stripped, first paragraph
    assert g["aliases"] == ["Example Bear"]                                            # own name removed from aliases
    assert [r["url"] for r in g["refs"]] == ["https://research.example.com/report"]   # non-http reference dropped
    assert not any(r["attack_id"] == "S9998" for r in rows)                            # deprecated skipped


def test_ingest_replaces_data_and_lookup_by_alias(conn, monkeypatch):
    n, etag, _ = _ingest(conn, monkeypatch)
    assert n == 61 + 321 and etag == '"abc"'
    hit = attack.lookup(conn, ["Example Bear"], "group")
    assert hit["attack_id"] == "G9999" and hit["url"] == "https://attack.mitre.org/groups/G9999"


def test_techniques_relationships_and_version(conn, monkeypatch):
    from app.db import get_setting
    _ingest(conn, monkeypatch)
    assert get_setting(conn, "attack_version") == "99.1"
    tactics = [r[0] for r in conn.execute("SELECT attack_id FROM attack_tactics ORDER BY ord")]
    assert tactics[0] == "TA0011"                                       # matrix order, not ID order
    t = conn.execute("SELECT * FROM attack_techniques WHERE attack_id='T1000'").fetchone()
    assert t["description"] == "Does a thing. cmd.exe" and json.loads(t["tactics"]) == ["tactic-0"]
    assert conn.execute("SELECT parent_id FROM attack_techniques WHERE attack_id='T1000.001'").fetchone()[0] == "T1000"
    assert not conn.execute("SELECT 1 FROM attack_techniques WHERE attack_id IN ('T0999','T0998')").fetchone()  # revoked, deprecated
    links = {tuple(r) for r in conn.execute("SELECT src, rel, dst FROM attack_links")}
    assert links == {("G9999", "uses", "T1000"), ("M1032", "mitigates", "T1000"), ("DET0001", "detects", "T1000")}
    assert conn.execute("SELECT new_id FROM attack_revoked WHERE old_id='T0999'").fetchone()[0] == "T1001"
    an = json.loads(conn.execute("SELECT analytics FROM attack_detections WHERE attack_id='DET0001'").fetchone()[0])
    assert an[0]["log_sources"] == [{"name": "WinEventLog:Security", "channel": "EventCode=4624"}]


def test_truncated_download_keeps_previous_data(conn, monkeypatch):
    def tiny(url, *, sink=None, **kw):
        sink.write(_bundle(n_tech=20))
        from app.ingest.fetcher import FetchResult
        return FetchResult(url=url, status=200)
    monkeypatch.setattr(attack, "fetch", tiny)
    import pytest
    with pytest.raises(ValueError):
        attack.ingest_attack(conn, {"url": "https://raw.githubusercontent.com/x.json"})


def test_further_reading_links():
    assert reading.technique_url("T1566.001") == "https://attack.mitre.org/techniques/T1566/001/"
    assert reading.technique_url("bogus") is None
    assert reading.safe_url("javascript:alert(1)") is None
    vulns = [{"cve_id": f"CVE-2099-{i:04d}", "references": [], "kev": False, "cve_url": f"https://www.cve.org/CVERecord?id=CVE-2099-{i:04d}"} for i in range(20)]
    vulns.append({"cve_id": "CVE-2099-9999", "references": ["https://vendor.example.com/advisory"], "kev": True, "epss": 0.5,
                  "cve_url": "https://www.cve.org/CVERecord?id=CVE-2099-9999", "kev_url": "https://www.cisa.gov/kev?CVE-2099-9999"})
    out = reading.for_article(None, [], vulns, "https://news.example.com/story")
    assert out[0]["section"].startswith("CVE-2099-9999") and out[0]["items"][0]["url"] == "https://vendor.example.com/advisory"
    assert out[1]["section"] == "More CVEs" and "20 more" in out[1]["note"]
