-- "Keep me signed in on this device": trusted sessions renew their expiry while the device keeps using the app.
ALTER TABLE sessions ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0;
