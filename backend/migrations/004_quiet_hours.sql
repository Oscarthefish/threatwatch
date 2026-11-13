-- Push notifications created during quiet hours are held and summarised in one push afterwards.
ALTER TABLE notifications ADD COLUMN push_held INTEGER NOT NULL DEFAULT 0;
