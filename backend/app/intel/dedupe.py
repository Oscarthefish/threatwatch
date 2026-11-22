"""URL canonicalisation and near-duplicate title detection."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_PARAMS = re.compile(
    r"^(utm_.*|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|ref|ref_src|cmpid|campaign|source|rss|feed|ito|sr_share|__twitter_impression)$",
    re.I,
)

STOPWORDS = set(
    """a an and are as at be by for from has have in into is it its of on or that the this to was were will with
    new how why what who after over amid via say says said report reports update updated warns warning""".split()
)


def canonical_url(url: str) -> str:
    p = urlsplit(url.strip())
    scheme = "https" if p.scheme in ("http", "https") else p.scheme
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = p.port
    netloc = host if not port or port in (80, 443) else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=False) if not TRACKING_PARAMS.match(k)))
    return urlunsplit((scheme, netloc, path, query, ""))


def title_tokens(title: str) -> set[str]:
    t = title.lower()
    t = re.sub(r"cve-(\d{4})-(\d+)", r"cve\1x\2", t)  # keep CVE ids as single tokens
    toks = re.findall(r"[a-z0-9$]+", t)
    return {w for w in toks if len(w) > 2 and w not in STOPWORDS}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def is_near_duplicate(tokens_a: set[str], tokens_b: set[str], shared_strong_entities: int) -> bool:
    j = jaccard(tokens_a, tokens_b)
    if j >= 0.75:
        return True
    return j >= 0.5 and shared_strong_entities > 0


# ------------------------------------------------------------- same-story grouping
# Outlets word the same story differently ("Optimizely supply chain attack infects major brands' sites" vs
# "Website management platform Optimizely confirms hackers put malicious code into customer sites"), so headline
# overlap alone almost never groups them. A shared distinctive *name* does: a product, company, malware or
# victim that few other recent headlines mention. Common names (agencies, countries, months, big vendors) are not
# distinctive and would chain unrelated stories together, so they never count on their own.
COMMON_NAMES = set(
    """hackers hacker attack attacks attackers malware data breach breaches vulnerability vulnerabilities exploited
    exploit exploits flaw flaws security critical patch patches patched users sites site customers million billion
    cyber cyberattack cyberattacks ransomware phishing campaign campaigns government police used use uses target
    targets targeting stolen steal steals threat actors actor group groups linked first more than zero day zeroday
    alert active actively windows microsoft google apple linux android cloud company firms firm agency
    cisa fbi nsa doj dhs ncsc nato europol interpol sec ftc treasury congress senate white house court
    january february march april may june july august september october november december
    monday tuesday wednesday thursday friday saturday sunday
    us usa uk eu china chinese russia russian iran iranian north korea korean israel israeli ukraine ukrainian
    france french germany german britain british australia australian zealand india japan canada european
    american italy spain business one net risky bulletin podcast stormcast isc sans ai""".split()
)
NAME_RARITY = 6        # a name in more recent headlines than this is too common to identify one story
NAME_ALONE_RARITY = 5  # rare enough that the shared name alone is enough
NAME_WINDOW_HOURS = 48


def headline_names(title: str) -> set[str] | None:
    """Lower-cased words capitalised mid-headline, or None for a Title Case headline (capitals say nothing there)."""
    words = re.findall(r"[A-Za-z][A-Za-z0-9]*", title)
    if not words or sum(w[0].isupper() for w in words) / len(words) > 0.6:
        return None
    return {w.lower() for w in words[1:] if w[0].isupper()}


def first_word(title: str) -> str:
    m = re.match(r"[^A-Za-z]*([A-Za-z][A-Za-z0-9]*)", title)
    return m.group(1).lower() if m else ""


def shared_names(title_a: str, title_b: str, shared_tokens: set[str]) -> list[str]:
    """Shared tokens that read as a name in at least one headline and are not ruled out by the other."""
    na, nb = headline_names(title_a), headline_names(title_b)
    if na is None and nb is None:
        return []
    fa, fb = first_word(title_a), first_word(title_b)
    out = []
    for t in sorted(shared_tokens):
        if len(t) < 3 or t.isdigit() or t in COMMON_NAMES:
            continue
        ok_a = na is None or t in na or t == fa
        ok_b = nb is None or t in nb or t == fb
        if ok_a and ok_b and ((na is not None and t in na) or (nb is not None and t in nb)):
            out.append(t)
    return out
