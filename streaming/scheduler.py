"""Scheduler — tâches périodiques Arctic + OSINT via APScheduler.

Démarrage : from streaming.scheduler import start_scheduler; start_scheduler(app)
Les tâches tournent en arrière-plan dans le contexte Flask.
"""
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


# ── tâches Arctic ─────────────────────────────────────────────────

def _task_ais():
    """Snapshot AIS — toutes les 15 min."""
    from arctic.ais_engine import AISEngine, ARCTIC_ZONES
    for zone, bounds in ARCTIC_ZONES.items():
        bbox = {
            "lat_min": bounds["lat"][0], "lat_max": bounds["lat"][1],
            "lon_min": bounds["lon"][0], "lon_max": bounds["lon"][1],
        }
        data = AISEngine().fetch(bbox)
        log.info("AIS %s: %d vessels", zone, data.get("count", 0))


def _task_adsb():
    """Snapshot ADS-B — toutes les 10 min."""
    from arctic.adsb_engine import ADSBEngine
    data = ADSBEngine().fetch({
        "lat_min": 60, "lat_max": 90,
        "lon_min": -141, "lon_max": -52,
    })
    log.info("ADS-B snapshot: %d flights", data.get("count", 0))


def _task_weather():
    """Météo toutes les stations nordiques — toutes les 30 min."""
    from arctic.weather_engine import WeatherEngine
    results = WeatherEngine().fetch_all()
    log.info("Weather: %d stations refreshed", len(results))


def _task_ice():
    """Métadonnées glace marine — 1×/jour."""
    from arctic.ice_engine import IceEngine
    data = IceEngine().fetch()
    log.info("Ice data refreshed: source=%s", data.get("source"))


# ── tâches OSINT ──────────────────────────────────────────────────

def _task_cve_refresh():
    """Purge du cache CVE expiré — toutes les 6h."""
    from models import db, CacheEntry
    from datetime import timezone
    expired = CacheEntry.query.filter(
        CacheEntry.expires_at < datetime.now(timezone.utc)
    ).all()
    for e in expired:
        db.session.delete(e)
    db.session.commit()
    log.info("Cache purge: %d entrées supprimées", len(expired))


# ── démarrage ─────────────────────────────────────────────────────

def start_scheduler(app) -> None:
    """Lance le scheduler dans le contexte Flask de l'app."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")

    def _ctx(fn):
        def wrapper():
            with app.app_context():
                fn()
        wrapper.__name__ = fn.__name__
        return wrapper

    _scheduler.add_job(_ctx(_task_ais),         IntervalTrigger(minutes=15),
                       id="ais",     replace_existing=True)
    _scheduler.add_job(_ctx(_task_adsb),        IntervalTrigger(minutes=10),
                       id="adsb",    replace_existing=True)
    _scheduler.add_job(_ctx(_task_weather),     IntervalTrigger(minutes=30),
                       id="weather", replace_existing=True)
    _scheduler.add_job(_ctx(_task_ice),         IntervalTrigger(hours=24),
                       id="ice",     replace_existing=True)
    _scheduler.add_job(_ctx(_task_cve_refresh), IntervalTrigger(hours=6),
                       id="cve_cache", replace_existing=True)

    _scheduler.start()
    log.info("Scheduler démarré — %d tâches actives", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("Scheduler arrêté")
