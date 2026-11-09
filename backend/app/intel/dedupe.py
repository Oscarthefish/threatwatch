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
