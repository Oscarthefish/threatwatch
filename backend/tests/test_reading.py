"""MITRE ATT&CK sync and further-reading links (synthetic STIX data, no network)."""
import json

from app.ingest import attack
from app.intel import reading


def _bundle(n_extra=60):
    objs = [
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


def test_stream_parser_and_cleaning(tmp_path):
    p = tmp_path / "b.json"
    p.write_bytes(_bundle())
    objs = list(attack.iter_objects(str(p), chunk=257))   # tiny chunks: objects span many reads
    assert len(objs) == 63
    rows = [r for o in objs if (r := attack.parse(o))]
    g = next(r for r in rows if r["attack_id"] == "G9999")
    assert g["description"] == "Example Group is a test group. It uses Tool."      # citations and links stripped, first paragraph
    assert g["aliases"] == ["Example Bear"]                                            # own name removed from aliases
    assert [r["url"] for r in g["refs"]] == ["https://research.example.com/report"]   # non-http reference dropped
    assert not any(r["attack_id"] == "S9998" for r in rows)                            # deprecated skipped


def test_ingest_replaces_data_and_lookup_by_alias(conn, monkeypatch):
    def fake_fetch(url, *, sink=None, **kw):
        sink.write(_bundle())
        from app.ingest.fetcher import FetchResult
        return FetchResult(url=url, status=200, headers={"etag": '"abc"'})
    monkeypatch.setattr(attack, "fetch", fake_fetch)
    n, etag, _ = attack.ingest_attack(conn, {"url": "https://raw.githubusercontent.com/x.json", "etag": None, "last_modified": None})
    assert n == 61 and etag == '"abc"'
    hit = attack.lookup(conn, ["Example Bear"], "group")
    assert hit["attack_id"] == "G9999" and hit["url"] == "https://attack.mitre.org/groups/G9999"


def test_truncated_download_keeps_previous_data(conn, monkeypatch):
    def tiny(url, *, sink=None, **kw):
        sink.write(_bundle(n_extra=3))
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
