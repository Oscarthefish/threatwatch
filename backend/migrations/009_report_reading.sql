-- Reading view and highlights for reports (derived from stored page text; re-computed when the analysis improves).
ALTER TABLE reports ADD COLUMN analysis TEXT;            -- JSON: running title, chapters, highlights
ALTER TABLE reports ADD COLUMN analysis_version INTEGER;
ALTER TABLE report_pages ADD COLUMN blocks TEXT;         -- JSON reading blocks: h | p | li | figure (+ vendor flag)
ALTER TABLE report_pages ADD COLUMN labels TEXT;         -- JSON running headers and section labels removed from the page
