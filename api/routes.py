"""Routes Flask — OSINT/TI + pipeline Arctique."""
from flask import Blueprint, jsonify, render_template, request

from core.aggregator import run_scan
from reporting.generator import build_report, report_to_json
from monitoring.delta import compute_delta, target_stats
from models import Scan, Target

bp = Blueprint("api", __name__)


# ── helpers ───────────────────────────────────────────────────────

def _guess_kind(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


# ── Dashboard ─────────────────────────────────────────────────────

@bp.get("/")
def dashboard():
    scans = Scan.query.order_by(Scan.started_at.desc()).limit(20).all()
    return render_template("dashboard.html", scans=scans)


# ── OSINT/TI ──────────────────────────────────────────────────────

@bp.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    kind = payload.get("kind") or _guess_kind(target)
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(run_scan(target, kind))


@bp.get("/api/report/<int:scan_id>")
def api_report(scan_id: int):
    try:
        return jsonify(build_report(scan_id))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@bp.get("/api/report/<int:scan_id>.json")
def api_report_json(scan_id: int):
    try:
        return report_to_json(scan_id), 200, {"Content-Type": "application/json"}
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@bp.get("/api/delta")
def api_delta():
    a = request.args.get("a", type=int)
    b = request.args.get("b", type=int)
    if not a or not b:
        return jsonify({"error": "params a and b required"}), 400
    try:
        return jsonify(compute_delta(a, b))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@bp.get("/api/targets")
def api_targets():
    return jsonify([
        {"value": t.value, "kind": t.kind, "scans": len(t.scans)}
        for t in Target.query.all()
    ])


@bp.get("/api/stats/<path:target_value>")
def api_stats(target_value: str):
    return jsonify(target_stats(target_value))


# ── Arctic pipeline ───────────────────────────────────────────────

@bp.get("/north/ais")
def north_ais():
    from arctic.ais_engine import AISEngine
    bbox = {
        "lat_min": float(request.args.get("lat_min", 60)),
        "lat_max": float(request.args.get("lat_max", 90)),
        "lon_min": float(request.args.get("lon_min", -141)),
        "lon_max": float(request.args.get("lon_max", -52)),
    }
    return jsonify(AISEngine().fetch(bbox))


@bp.get("/north/adsb")
def north_adsb():
    from arctic.adsb_engine import ADSBEngine
    bbox = {
        "lat_min": float(request.args.get("lat_min", 60)),
        "lat_max": float(request.args.get("lat_max", 90)),
        "lon_min": float(request.args.get("lon_min", -141)),
        "lon_max": float(request.args.get("lon_max", -52)),
    }
    return jsonify(ADSBEngine().fetch(bbox))


@bp.get("/north/ice")
def north_ice():
    from arctic.ice_engine import IceEngine
    return jsonify(IceEngine().fetch())


@bp.get("/north/weather")
def north_weather():
    from arctic.weather_engine import WeatherEngine
    station = request.args.get("station", "CYRB")  # Resolute Bay par défaut
    return jsonify(WeatherEngine().fetch(station))


@bp.get("/north/infrastructure")
def north_infra():
    from arctic.infra_engine import InfraEngine
    region = request.args.get("region", "nunavut")
    return jsonify(InfraEngine().fetch(region))


@bp.get("/north/geo")
def north_geo():
    from arctic.geo_engine import GeoEngine
    return jsonify(GeoEngine().fetch())


@bp.get("/north/satellite")
def north_satellite():
    from arctic.satellite_engine import SatelliteEngine
    days = request.args.get("days", 5, type=int)
    aoi  = request.args.get("aoi")
    eng  = SatelliteEngine()
    if aoi:
        return jsonify(eng.fetch_aoi(aoi, days_back=days))
    bbox = {
        "lat_min": float(request.args.get("lat_min", 60)),
        "lat_max": float(request.args.get("lat_max", 90)),
        "lon_min": float(request.args.get("lon_min", -141)),
        "lon_max": float(request.args.get("lon_max", -52)),
    }
    return jsonify(eng.fetch(bbox=bbox, days_back=days))


@bp.get("/north/map")
def north_map():
    """Carte Folium interactive des zones Arctique."""
    from arctic.geo_engine import GeoEngine
    html = GeoEngine().render_map()
    return html, 200, {"Content-Type": "text/html"}
