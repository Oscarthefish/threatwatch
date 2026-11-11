-- SecOps next steps derived per article (see app/intel/actions.py). Recomputed whenever an article is processed.
ALTER TABLE articles ADD COLUMN actions TEXT NOT NULL DEFAULT '[]';
