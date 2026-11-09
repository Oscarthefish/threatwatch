"""FastAPI application: API + static PWA assets."""
from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import auth
from .api import content, user, watches
from .config import get_settings
from .db import connect, get_setting, migrate
from .ingest.pipeline import sync_sources

log = logging.getLogger("threatwatch")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'; object-src 'none'")


class LoginIn(BaseModel):
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=500)


def create_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    s = get_settings()
    conn = connect()
    migrate(conn)
    sync_sources(conn)
    conn.close()

    app = FastAPI(title="Threat Watch", docs_url=None, redoc_url=None, openapi_url=None)
    hosts = [h.strip() for h in s.trusted_hosts.split(",") if h.strip()]
    if hosts and hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*hosts, "localhost", "127.0.0.1"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if s.cookie_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        path = request.url.path
        if path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        elif path.startswith("/assets/"):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path in ("/", "/index.html", "/sw.js", "/manifest.webmanifest") or "." not in path.rsplit("/", 1)[-1]:
            resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # never leak internals
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"detail": "Internal error"}, status_code=500)

    @app.get("/api/health")
    def health():
        try:
            c = connect()
            c.execute("SELECT 1").fetchone()
            hb = get_setting(c, "worker_heartbeat")
            c.close()
        except sqlite3.Error:
            raise HTTPException(503, "database unavailable")
        return {"status": "ok", "worker_heartbeat": hb}

    @app.post("/api/auth/login")
    def login(body: LoginIn, request: Request, response: Response, conn: sqlite3.Connection = Depends(auth.get_db)):
        return auth.login(conn, request, response, body.username, body.password)

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response, conn: sqlite3.Connection = Depends(auth.get_db)):
        auth.logout(conn, request, response)
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(u: dict = Depends(auth.require_user), conn: sqlite3.Connection = Depends(auth.get_db)):
        unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE digest_pending=0 AND read_at IS NULL").fetchone()[0]
        return {"username": u["username"], "unread_notifications": unread, "ai_enabled": s.ai_enabled}

    app.include_router(content.router)
    app.include_router(user.router)
    app.include_router(watches.router)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def api_404(rest: str):
        raise HTTPException(404, "not found")

    static = s.static_dir
    if static and Path(static).is_dir():
        root = Path(static).resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            # Static assets are public (no data); all data flows through authenticated /api routes.
            candidate = (root / path).resolve()
            if path and candidate.is_file() and root in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(root / "index.html")

    return app


