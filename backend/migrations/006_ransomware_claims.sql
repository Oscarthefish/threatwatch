-- Ransomware leak-site claims, as aggregated by ransomware.live. These are the groups' own claims, not
-- confirmed compromises. Only identifying fields are kept: no leak descriptions, screenshots or leak-site links.
CREATE TABLE ransomware_claims (
    id            INTEGER PRIMARY KEY,
    record_url    TEXT NOT NULL UNIQUE,     -- the tracker's page for this claim (https://www.ransomware.live/id/...)
    group_raw     TEXT NOT NULL,            -- group name as the tracker publishes it
    group_name    TEXT NOT NULL,            -- canonical name (Threat Watch dictionary) when known
    victim        TEXT NOT NULL,
    domain        TEXT,
    country       TEXT,                     -- ISO 3166-1 alpha-2, upper case
    sector        TEXT,
    attack_date   TEXT,                     -- date the group gives, when it gives one
    discovered_at TEXT NOT NULL,            -- when the tracker first saw the post (UTC ISO)
    retrieved_at  TEXT NOT NULL
);
CREATE INDEX idx_claims_discovered ON ransomware_claims(discovered_at DESC);
CREATE INDEX idx_claims_group ON ransomware_claims(group_name, discovered_at DESC);
CREATE INDEX idx_claims_country ON ransomware_claims(country, discovered_at DESC);
