"""Scheduled ingestion worker (separate process from the API).

Jobs:
  * ingest       every TW_INGEST_INTERVAL_MINUTES (per-source intervals respected)
  * briefing     daily at TW_BRIEFING_HOUR:TW_BRIEFING_MINUTE Pacific/Auckland
  * digest       daily, five minutes after the briefing
  * maintenance  daily retention pruning + SQLite optimise
  * on-demand    polls every minute for "refresh now" requests made from the UI
"""
from __future__ import annotations

import logging
import signal
import sys
import threading

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .config import get_settings
from .db import connect, get_setting, migrate, now_iso, set_setting, tx
from .ingest import pipeline
from .intel import briefing, notify, watch

log = logging.getLogger("threatwatch.worker")
_lock = threading.Lock()


def ingest_cycle(force: bool = False) -> dict:
    if not _lock.acquire(blocking=False):
        log.info("ingest already running; skipping")
        return {}
    conn = connect()
    try:
        migrate(conn)
        report = pipeline.run_ingest(conn, force=force)
        new_ids = report.get("new_articles", [])
        summarised = pipeline.summarise_new(conn, new_ids)
        linked = watch.match_new_articles(conn, new_ids)
        set_setting(conn, "last_ingest_at", now_iso())
        log.info("ingest: %d new articles, %d AI summaries, watch links %s, sources %s",
                 len(new_ids), summarised, linked, report.get("sources"))
        return report
    except Exception:
        log.exception("ingest cycle failed")
        return {}
    finally:
        conn.close()
        _lock.release()


def briefing_job() -> None:
    conn = connect()
    try:
        bid = briefing.generate(conn)
        log.info("briefing %s generated", bid)
    except Exception:
        log.exception("briefing failed")
    finally:
        conn.close()


def digest_job() -> None:
    conn = connect()
    try:
        notify.compile_digest(conn, briefing.local_today())
    finally:
        conn.close()


def maintenance_job() -> None:
    conn = connect()
    try:
        with tx(conn):
            n = pipeline.prune(conn)
        conn.execute("INSERT INTO articles_fts(articles_fts) VALUES('optimize')")
        conn.execute("PRAGMA optimize")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info("maintenance: pruned %d articles", n)
    finally:
        conn.close()


def poll_requests() -> None:
    conn = connect()
    try:
        req = get_setting(conn, "ingest_requested")
        if req:
            set_setting(conn, "ingest_requested", None)
        breq = get_setting(conn, "briefing_requested")
        if breq:
            set_setting(conn, "briefing_requested", None)
        set_setting(conn, "worker_heartbeat", now_iso())
        from .intel.notify import release_held
        held = release_held(conn)  # one summary push once quiet hours end (no-op otherwise)
        if held:
            log.info("quiet hours over: summarised %d held alert(s) in one push", held)
    finally:
        conn.close()
    if req:
        ingest_cycle(force=True)
    if breq:
        briefing_job()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = get_settings()
    conn = connect()
    migrate(conn)
    pipeline.sync_sources(conn)
    n = pipeline.backfill_actions(conn)
    if n:
        log.info("computed SecOps actions for %d stored articles", n)
    from .intel.watch import reevaluate_all
    n = reevaluate_all(conn)
    if n:
        log.info("re-checked %d followed items with updated matching rules", n)
    n = pipeline.clean_stored_text(conn)
    if n:
        log.info("decoded leftover HTML entities in %d stored articles", n)
    from .intel.watch import reassess_all
    n = reassess_all(conn)
    if n:
        log.info("re-assessed %d linked reports with stricter relevance rules", n)
    has_briefing = conn.execute("SELECT 1 FROM briefings LIMIT 1").fetchone()
    conn.close()
    log.info("worker starting; AI %s; interval %d min", "enabled" if s.ai_enabled else "disabled", s.ingest_interval_minutes)

    sched = BlockingScheduler(timezone=s.timezone, job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    sched.add_job(ingest_cycle, IntervalTrigger(minutes=s.ingest_interval_minutes), id="ingest")
    sched.add_job(briefing_job, CronTrigger(hour=s.briefing_hour, minute=s.briefing_minute), id="briefing")
    sched.add_job(digest_job, CronTrigger(hour=s.briefing_hour, minute=(s.briefing_minute + 5) % 60), id="digest")
    sched.add_job(maintenance_job, CronTrigger(hour=3, minute=30), id="maintenance")
    sched.add_job(poll_requests, IntervalTrigger(seconds=30), id="poll")

    def startup():
        ingest_cycle()
        if not has_briefing:
            briefing_job()

    threading.Thread(target=startup, daemon=True).start()

    def stop(*_):
        log.info("worker stopping")
        sched.shutdown(wait=False)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sched.start()


if __name__ == "__main__":
    main()
