-- MITRE ATT&CK groups and software, synced weekly from the public mitre/cti repository.
CREATE TABLE IF NOT EXISTS attack_objects (
    stix_id     TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,            -- group | software
    attack_id   TEXT NOT NULL,            -- G0007, S0154
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL,
    refs        TEXT NOT NULL DEFAULT '[]',  -- [{source, url, description}] as cited by MITRE
    modified    TEXT,
    synced_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_name ON attack_objects(lower(name));
