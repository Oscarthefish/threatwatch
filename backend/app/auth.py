"""Single-user authentication with server-side sessions.

* Passwords hashed with Argon2id (argon2-cffi defaults).
* Session cookie: random 256-bit token, HttpOnly, Secure, SameSite=Strict.
  Only the SHA-256 of the token is stored in the database.
* Unsafe methods additionally require the ``X-TW-Request: 1`` header, which a
  cross-site form cannot send (CSRF defence in depth on top of SameSite=Strict).
* Login attempts are rate limited per client and globally.
* "Keep me signed in on this device" creates a *trusted* session: its server-side
  expiry (and the cookie) is pushed forward at most once a day while the device
  keeps using the app, so it ends after ``trusted_session_days`` without use.
  Normal sessions keep a fixed ``session_days`` lifetime. Any session can be
  signed out from Settings, which deletes it server-side.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response, status

from .config import get_settings
from .db import connect, iso, now_iso, utcnow

COOKIE = "tw_session"
CSRF_HEADER = "x-tw-request"
_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


def hash_password(pw: str) -> str:
    if len(pw) < 12:
        raise ValueError("password must be at least 12 characters")
    return _ph.hash(pw)


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def client_id(request: Request) -> str:
    # Behind Tailscale Serve / cloudflared the peer is the local proxy; prefer the
    # header those proxies set, but only as a rate-limit key (never for authz).
    for h in ("cf-connecting-ip", "tailscale-user-login", "x-forwarded-for"):
        v = request.headers.get(h)
        if v:
            return v.split(",")[0].strip()[:100]
    return request.client.host if request.client else "unknown"


def _too_many_attempts(conn: sqlite3.Connection, client: str) -> bool:
    s = get_settings()
    since = iso(utcnow() - timedelta(minutes=15))
    per_client = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE client=? AND at>=? AND success=0", (client, since)).fetchone()[0]
    overall = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE at>=? AND success=0", (since,)).fetchone()[0]
    return per_client >= s.login_max_attempts or overall >= s.login_max_attempts * 4


def login(conn: sqlite3.Connection, request: Request, response: Response, username: str, password: str,
          remember: bool = False) -> dict:
    client = client_id(request)
    if _too_many_attempts(conn, client):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again in 15 minutes.")
    row = conn.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
    ok = False
    try:
        ok = _ph.verify(row["password_hash"] if row else _DUMMY_HASH, password) and row is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False
    conn.execute("INSERT INTO login_attempts(client, at, success) VALUES(?,?,?)", (client, now_iso(), int(ok)))
    if not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if _ph.check_needs_rehash(row["password_hash"]):
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (_ph.hash(password), row["id"]))
    token = secrets.token_urlsafe(32)
    days = _days(remember)
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, created_at, expires_at, last_seen, user_agent, trusted) VALUES(?,?,?,?,?,?,?)",
        (_h(token), row["id"], now_iso(), iso(utcnow() + timedelta(days=days)), now_iso(),
         (request.headers.get("user-agent") or "")[:200], int(remember)),
    )
    _set_cookie(response, token, days)
    return {"username": row["username"], "trusted": remember}


def _days(trusted: bool) -> int:
    s = get_settings()
    return s.trusted_session_days if trusted else s.session_days


def _set_cookie(response: Response, token: str, days: int) -> None:
    response.set_cookie(COOKIE, token, max_age=days * 86400, httponly=True, secure=get_settings().cookie_secure,
                        samesite="strict", path="/")


def renew_trusted(conn: sqlite3.Connection, request: Request, response: Response, user: dict) -> None:
    """Push a trusted session's expiry forward, at most once a day (called from /api/auth/me)."""
    if not user.get("trusted"):
        return
    days = _days(True)
    if user["expires_at"] > iso(utcnow() + timedelta(days=days - 1)):
        return
    conn.execute("UPDATE sessions SET expires_at=? WHERE token_hash=?",
                 (iso(utcnow() + timedelta(days=days)), user["token_hash"]))
    _set_cookie(response, request.cookies[COOKIE], days)


def device_label(user_agent: str | None) -> str:
    ua = user_agent or ""
    system = next((name for pat, name in (
        (r"Android", "Android"), (r"iPhone", "iPhone"), (r"iPad", "iPad"), (r"Macintosh|Mac OS X", "Mac"),
        (r"Windows", "Windows"), (r"CrOS", "ChromeOS"), (r"Linux", "Linux")) if re.search(pat, ua)), "Unknown device")
    browser = next((name for pat, name in (
        (r"Edg/", "Edge"), (r"Firefox/|FxiOS", "Firefox"), (r"SamsungBrowser", "Samsung Internet"),
        (r"Chrome/|CriOS", "Chrome"), (r"Safari/", "Safari")) if re.search(pat, ua)), "")
    return f"{browser} on {system}" if browser else system


def list_sessions(conn: sqlite3.Connection, user: dict) -> list[dict]:
    rows = conn.execute(
        "SELECT rowid AS id, token_hash, created_at, last_seen, expires_at, trusted, user_agent FROM sessions "
        "WHERE user_id=? AND expires_at>=? ORDER BY last_seen DESC", (user["user_id"], now_iso())).fetchall()
    return [{"id": r["id"], "device": device_label(r["user_agent"]), "signed_in_at": r["created_at"],
             "last_seen": r["last_seen"], "expires_at": r["expires_at"], "trusted": bool(r["trusted"]),
             "current": r["token_hash"] == user["token_hash"]} for r in rows]


def revoke_session(conn: sqlite3.Connection, user: dict, session_id: int) -> bool:
    return conn.execute("DELETE FROM sessions WHERE rowid=? AND user_id=?", (session_id, user["user_id"])).rowcount > 0


def logout(conn: sqlite3.Connection, request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE)
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_h(token),))
    response.delete_cookie(COOKIE, path="/")


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_user(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    row = conn.execute(
        "SELECT s.*, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (_h(token),)
    ).fetchone()
    if not row or row["expires_at"] < now_iso():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing request header")
    if row["last_seen"] < iso(utcnow() - timedelta(minutes=10)):
        conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now_iso(), row["token_hash"]))
    return {"user_id": row["user_id"], "username": row["username"], "trusted": bool(row["trusted"]),
            "expires_at": row["expires_at"], "token_hash": row["token_hash"]}
