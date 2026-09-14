"""Delta Engine — détection de changements Arctic + alertes.

Compare les snapshots successifs des sources Arctic pour détecter :
  - Apparition/disparition de vessels (AIS)
  - Nouveaux vols (ADS-B)
  - Dégradation conditions météo
  - Changements infrastructure
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# Seuils d'alerte
ALERT_THRESHOLDS = {
    "ais_new_vessels":  3,    # >3 nouveaux vessels = alerte
    "adsb_new_flights": 5,    # >5 nouveaux vols = alerte
    "wind_kt":          35,   # tempête
    "visibility_m":     400,  # white-out
    "temp_c":          -40,   # froid extrême
}

_snapshots: dict[str, dict] = {}  # mémoire courte (RAM) entre tâches


def _digest(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


def snapshot(source: str, data: dict) -> dict:
    """Enregistre un snapshot et retourne le delta vs snapshot précédent."""
    ts = datetime.now(timezone.utc).isoformat()
    current_digest = _digest(data)
    prev = _snapshots.get(source)

    delta: dict = {
        "source":    source,
        "timestamp": ts,
        "digest":    current_digest,
        "changed":   False,
        "alerts":    [],
    }

    if prev:
        if prev["digest"] != current_digest:
            delta["changed"] = True
            delta["alerts"]  = _detect_alerts(source, prev["data"], data)
            log.info("Delta %s: changement détecté — %d alertes",
                     source, len(delta["alerts"]))

    _snapshots[source] = {"digest": current_digest, "data": data, "ts": ts}
    return delta


def _detect_alerts(source: str, before: dict, after: dict) -> list[dict]:
    alerts = []

    if source == "ais":
        mmsi_before = {v["mmsi"] for v in before.get("vessels", []) if v.get("mmsi")}
        mmsi_after  = {v["mmsi"] for v in after.get("vessels",  []) if v.get("mmsi")}
        new_vessels = mmsi_after - mmsi_before
        gone        = mmsi_before - mmsi_after
        if len(new_vessels) >= ALERT_THRESHOLDS["ais_new_vessels"]:
            alerts.append({
                "level":   "HIGH",
                "type":    "ais_surge",
                "message": f"{len(new_vessels)} nouveaux vessels détectés",
                "mmsi":    list(new_vessels),
            })
        if gone:
            alerts.append({
                "level":   "INFO",
                "type":    "ais_departure",
                "message": f"{len(gone)} vessels ont quitté la zone",
            })

    elif source == "adsb":
        before_ids = {f.get("icao24") for f in before.get("flights", [])}
        after_ids  = {f.get("icao24") for f in after.get("flights",  [])}
        new_flights = after_ids - before_ids
        if len(new_flights) >= ALERT_THRESHOLDS["adsb_new_flights"]:
            alerts.append({
                "level":   "MEDIUM",
                "type":    "adsb_surge",
                "message": f"{len(new_flights)} nouveaux vols détectés",
            })

    elif source == "weather":
        metar_b = before.get("metar_raw", "")
        metar_a = after.get("metar_raw", "")
        if metar_b != metar_a:
            alerts.append({
                "level":   "INFO",
                "type":    "weather_change",
                "message": "Conditions météo modifiées",
                "before":  metar_b,
                "after":   metar_a,
            })

    return alerts


def get_all_snapshots() -> dict:
    return {
        source: {
            "digest": snap["digest"],
            "ts":     snap["ts"],
        }
        for source, snap in _snapshots.items()
    }
