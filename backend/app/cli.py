"""Administrative CLI.

    python -m app.cli set-password [username]   # interactive, never echoes
    python -m app.cli ingest [--force]          # one ingestion cycle
    python -m app.cli briefing                  # generate a briefing now
    python -m app.cli sources                   # source health table
    python -m app.cli reprocess                 # re-run extraction/classification on stored articles
    python -m app.cli vapid                     # generate Web Push VAPID keys
    python -m app.cli backup <dest.db>          # consistent online backup
"""
from __future__ import annotations

import argparse
import getpass
import logging
import sqlite3
import sys

from .auth import hash_password
from .db import connect, migrate, now_iso


def cmd_set_password(args) -> int:
    conn = connect()
    migrate(conn)
    username = args.username or input("Username: ").strip()
    if not username:
        print("username required", file=sys.stderr)
        return 2
    pw = getpass.getpass("New password (min 12 chars): ")
    if pw != getpass.getpass("Repeat password: "):
        print("passwords do not match", file=sys.stderr)
        return 2
    try:
        h = hash_password(pw)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    conn.execute(
        "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
        (username, h, now_iso()))
    conn.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)", (username,))
    print(f"password set for {username}; existing sessions revoked")
    return 0


def cmd_ingest(args) -> int:
    from .worker import ingest_cycle

    logging.basicConfig(level=logging.INFO)
    r = ingest_cycle(force=args.force)
    for k, v in (r.get("sources") or {}).items():
        print(f"{k:28s} {v}")
    print(f"new articles: {len(r.get('new_articles', []))}")
    return 0


def cmd_briefing(args) -> int:
    from .intel import briefing

    conn = connect()
    migrate(conn)
    print("briefing id", briefing.generate(conn))
    return 0


def cmd_sources(args) -> int:
    conn = connect()
    migrate(conn)
    for r in conn.execute("SELECT key, enabled, last_status, last_success_at, items_last_run, last_error FROM sources ORDER BY key"):
        print(f"{r['key']:26s} {'on ' if r['enabled'] else 'off'} {r['last_status'] or '-':12s} {r['last_success_at'] or '-':26s} {r['items_last_run'] or 0:4d} {(r['last_error'] or '')[:60]}")
    return 0


def cmd_reprocess(args) -> int:
    """Re-run extraction/classification/clustering for all articles (after rule changes)."""
    from .db import tx
    from .ingest.pipeline import process_article

    conn = connect()
    migrate(conn)
    ids = [r[0] for r in conn.execute("SELECT id FROM articles ORDER BY id")]
    conn.execute("UPDATE articles SET cluster_id=NULL")
    for aid in ids:
        with tx(conn):
            process_article(conn, aid)
    print(f"reprocessed {len(ids)} articles")
    return 0


def cmd_vapid(args) -> int:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print("cryptography not installed", file=sys.stderr)
        return 2
    import base64

    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_numbers().private_value.to_bytes(32, "big")
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    print("Add these to your secrets env file (do not commit):")
    print(f"TW_VAPID_PUBLIC_KEY={b64(pub)}")
    print(f"TW_VAPID_PRIVATE_KEY={b64(priv)}")
    return 0


def cmd_backup(args) -> int:
    import os
    from pathlib import Path

    out = Path(args.dest)
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    src = connect()
    dest = sqlite3.connect(out)
    with dest:
        src.backup(dest)
    dest.close()
    os.chmod(out, 0o600)
    print(f"backup written to {args.dest}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="threatwatch")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("set-password"); sp.add_argument("username", nargs="?"); sp.set_defaults(fn=cmd_set_password)
    si = sub.add_parser("ingest"); si.add_argument("--force", action="store_true"); si.set_defaults(fn=cmd_ingest)
    sub.add_parser("briefing").set_defaults(fn=cmd_briefing)
    sub.add_parser("sources").set_defaults(fn=cmd_sources)
    sub.add_parser("vapid").set_defaults(fn=cmd_vapid)
    sub.add_parser("reprocess").set_defaults(fn=cmd_reprocess)
    sb = sub.add_parser("backup"); sb.add_argument("dest"); sb.set_defaults(fn=cmd_backup)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
