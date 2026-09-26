"""Scheduler — tâches périodiques Arctic + OSINT via APScheduler.

Démarrage : from streaming.scheduler import start_scheduler; start_scheduler(app)
Les tâches tournent en arrière-plan dans le contexte Flask.
"""
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None

# Toutes les tâches : grace period 60 s, une seule instance simultanée
_JOB_DEFAULTS = {
    "coalesce": True,           # fusionne les exécutions manquées en une seule
    "max_instances": 1,         # interdit les instances parallèles du même job
    "misfire_grace_time": 60,   # tolère 60 s de retard avant de marquer raté
}


# ── tâches Arctic ─────────────────────────────────────────────────

def _task_ais():
    """Snapshot AIS — toutes les 15 min."""
    try:
        from arctic.ais_engine import AISEngine, ARCTIC_ZONES
        for zone, bounds in ARCTIC_ZONES.items():
            bbox = {
                "lat_min": bounds["lat"][0], "lat_max": bounds["lat"][1],
                "lon_min": bounds["lon"][0], "lon_max": bounds["lon"][1],
            }
            data = AISEngine().fetch(bbox)
            log.info("AIS %s: %d vessels", zone, data.get("count", 0))
    except Exception:
        log.exception("Échec tâche AIS")


def _task_adsb():
    """Snapshot ADS-B — toutes les 10 min."""
    try:
        from arctic.adsb_engine import ADSBEngine
        data = ADSBEngine().fetch({
            "lat_min": 60, "lat_max": 90,
            "lon_min": -141, "lon_max": -52,
        })
        log.info("ADS-B snapshot: %d flights", data.get("count", 0))
    except Exception:
        log.exception("Échec tâche ADS-B")


def _task_weather():
    """Météo toutes les stations nordiques — toutes les 30 min."""
    try:
        from arctic.weather_engine import WeatherEngine
        results = WeatherEngine().fetch_all()
        log.info("Weather: %d stations refreshed", len(results))
    except Exception:
        log.exception("Échec tâche Weather")


def _task_ice():
    """Métadonnées glace marine — 1×/jour."""
    try:
        from arctic.ice_engine import IceEngine
        data = IceEngine().fetch()
        log.info("Ice data refreshed: source=%s", data.get("source"))
    except Exception:
        log.exception("Échec tâche Ice")


# ── tâches OSINT ──────────────────────────────────────────────────

def _task_cve_refresh():
    """Purge du cache CVE expiré — toutes les 6h."""
    try:
        from models import db, CacheEntry
        expired = CacheEntry.query.filter(
            CacheEntry.expires_at < datetime.now(timezone.utc)
        ).all()
        count = len(expired)
        for e in expired:
            db.session.delete(e)
        db.session.commit()
        log.info("Cache purge: %d entrées supprimées", count)
    except Exception:
        log.exception("Échec tâche CVE cache refresh")


# ── démarrage ─────────────────────────────────────────────────────

def _on_job_error(event) -> None:
    log.error("Job %s a levé une exception : %s", event.job_id, event.exception)


def _on_job_missed(event) -> None:
    log.warning("Job %s a manqué son exécution planifiée", event.job_id)


def start_scheduler(app) -> None:
    """Lance le scheduler dans le contexte Flask de l'app."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(
        timezone="UTC",
        job_defaults=_JOB_DEFAULTS,
        executors={"default": {"type": "threadpool", "max_workers": 4}},
    )

    _scheduler.add_listener(_on_job_error, EVENT_JOB_ERROR)
    _scheduler.add_listener(_on_job_missed, EVENT_JOB_MISSED)

    def _ctx(fn):
        """Wraps a task so it runs inside the Flask app context."""
        def wrapper():
            with app.app_context():
                fn()
        wrapper.__name__ = fn.__name__
        return wrapper

    _scheduler.add_job(_ctx(_task_ais),         IntervalTrigger(minutes=15),
                       id="ais",       replace_existing=True)
    _scheduler.add_job(_ctx(_task_adsb),        IntervalTrigger(minutes=10),
                       id="adsb",      replace_existing=True)
    _scheduler.add_job(_ctx(_task_weather),     IntervalTrigger(minutes=30),
                       id="weather",   replace_existing=True)
    _scheduler.add_job(_ctx(_task_ice),         IntervalTrigger(hours=24),
                       id="ice",       replace_existing=True)
    _scheduler.add_job(_ctx(_task_cve_refresh), IntervalTrigger(hours=6),
                       id="cve_cache", replace_existing=True)

    _scheduler.start()
    log.info("Scheduler démarré — %d tâches actives", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("Scheduler arrêté")
