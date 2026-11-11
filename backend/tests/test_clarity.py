"""Display text, date checks and follow-alert relevance (synthetic data only)."""
from datetime import datetime, timezone

from app.intel import text
from app.intel.watch import _heuristic_assess


def test_excerpt_word_boundary_and_publisher_marker():
    long = "Alpha beta gamma. " * 30
    out = text.excerpt(long, 100)
    assert len(out) <= 101 and out.endswith(".")
    cut = text.excerpt("word " * 80 + "Vulnerabi", 120)
    assert cut.endswith("…") and "Vulnerabi" not in cut
    assert text.excerpt("Short summary [...]") == "Short summary…"


def test_entities_decoded_even_when_escaped_twice():
    assert text.excerpt("tracked as (&amp;quot;Example&amp;quot;) and People&#039;s") == 'tracked as ("Example") and People\'s'


def test_date_notes():
    now = datetime(2098, 12, 1, tzinfo=timezone.utc)
    assert text.date_notes("Example Patch Tuesday November 2099", "2098-11-10T18:00:00Z", "2098-11-10T19:00:00Z", now=now)
    assert text.date_notes("Example", "2098-12-05T00:00:00Z", None, now=now)  # future-dated
    assert not text.date_notes("Example trends for 2099", "2098-10-10T00:00:00Z", None, now=now)
    assert not text.date_notes("Example roundup for Wednesday, November 11th, 2098", "2098-11-11T02:00:00Z", None, now=now)
    assert not text.date_notes("Exploitation of a May 2098 flaw", "2098-10-20T00:00:00Z", None, now=now)


def test_passages_highlight_the_matching_sentence():
    t = "Vendor A fixed bugs. Separately, CVE-2099-0001 in Example Browser was exploited in the wild. Actor X hit a hospital."
    p = text.passages(t, ["CVE-2099-0001"])
    assert len(p) == 1 and p[0]["text"].startswith("Separately") and p[0]["terms"] == ["CVE-2099-0001"]


def _ev(**kw):
    base = {"title": "", "summary_text": "", "content_text": "", "tags": "[]", "cluster_id": 1, "severity": 3,
            "authority": 1, "source_name": "Example News"}
    return base | kw


def test_bulletin_does_not_report_unrelated_cves_as_changes():
    e = _ev(title="CISA Adds Six Known Exploited Vulnerabilities to Catalog", authority=3, source_name="Example CERT",
            summary_text="CVE-2099-0001 Example Browser use-after-free. CVE-2099-0002 Example VPN bypass. CVE-2099-0003 Example Mail flaw.")
    ents = {("cve", "cve-2099-0001"), ("cve", "cve-2099-0002"), ("cve", "cve-2099-0003"), ("cve", "cve-2099-0004")}
    sig, why = _heuristic_assess(e, ["CVE-2099-0001"], set(), set(), ents, {"Example News"})
    assert sig == "important" and "KEV" in why
    assert "cve-2099-0002" not in why.lower() and "3 other items" in why


def test_roundup_mentions_are_minor():
    e = _ev(title="Example Weekly: news roundup", tags='["roundup"]',
            summary_text="CVE-2099-0001 was patched. Actor X used ExampleLoader against a retailer and was exploited in attacks.")
    sig, _ = _heuristic_assess(e, ["CVE-2099-0001"], set(), set(), {("actor", "actor x"), ("malware", "exampleloader")}, set())
    assert sig == "minor"


def test_single_subject_report_names_related_entities():
    e = _ev(title="ExampleLoader used to exploit CVE-2099-0001", summary_text="Actor X exploited CVE-2099-0001 to deploy ExampleLoader.")
    sig, why = _heuristic_assess(e, ["CVE-2099-0001"], set(), set(), {("actor", "actor x"), ("malware", "exampleloader")}, {"Example News"})
    assert sig == "important" and "actor x" in why.lower()
