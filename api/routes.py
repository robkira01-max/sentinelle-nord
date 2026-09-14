"""Routes Flask — OSINT/TI + pipeline Arctique."""
from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from core.aggregator import run_scan
from extensions import limiter
from reporting.generator import build_report, report_to_json
from monitoring.delta import compute_delta, target_stats
from models import Scan, Target

bp = Blueprint("api", __name__)

_LAT_RANGE = (-90.0, 90.0)
_LON_RANGE = (-180.0, 180.0)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _guess_kind(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def _parse_bbox(defaults: tuple = (60, 90, -141, -52)) -> dict:
    """Parse et valide une bounding box depuis les query params."""
    lat_min_d, lat_max_d, lon_min_d, lon_max_d = defaults
    try:
        lat_min = float(request.args.get("lat_min", lat_min_d))
        lat_max = float(request.args.get("lat_max", lat_max_d))
        lon_min = float(request.args.get("lon_min", lon_min_d))
        lon_max = float(request.args.get("lon_max", lon_max_d))
    except (TypeError, ValueError):
        raise ValueError("bbox params must be numeric floats")
    if not (_LAT_RANGE[0] <= lat_min <= _LAT_RANGE[1] and
            _LAT_RANGE[0] <= lat_max <= _LAT_RANGE[1]):
        raise ValueError("lat_min/lat_max must be in [-90, 90]")
    if not (_LON_RANGE[0] <= lon_min <= _LON_RANGE[1] and
            _LON_RANGE[0] <= lon_max <= _LON_RANGE[1]):
        raise ValueError("lon_min/lon_max must be in [-180, 180]")
    if lat_min >= lat_max or lon_min >= lon_max:
        raise ValueError("lat_min < lat_max and lon_min < lon_max required")
    return {"lat_min": lat_min, "lat_max": lat_max,
            "lon_min": lon_min, "lon_max": lon_max}


def _api_login_required(f):
    """Comme @login_required mais retourne 401 JSON pour les appels API."""
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "authentication required"}), 401
        return f(*args, **kwargs)
    return wrapped


def _require_scan_role(f):
    """Requiert le rôle analyst ou admin pour lancer un scan."""
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "authentication required"}), 401
        if not current_user.can_scan():
            return jsonify({"error": "forbidden — analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return wrapped


# ── Dashboard ──────────────────────────────────────────────────────────────────

@bp.get("/")
@login_required
def dashboard():
    scans = Scan.query.order_by(Scan.started_at.desc()).limit(20).all()
    return render_template("dashboard.html", scans=scans)


# ── OSINT/TI ───────────────────────────────────────────────────────────────────

@bp.post("/api/scan")
@_require_scan_role
@limiter.limit("10 per minute; 50 per hour")
def api_scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    kind = payload.get("kind") or _guess_kind(target)
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(run_scan(target, kind))


@bp.get("/api/report/<int:scan_id>")
@_api_login_required
def api_report(scan_id: int):
    try:
        return jsonify(build_report(scan_id))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@bp.get("/api/report/<int:scan_id>.json")
@_api_login_required
def api_report_json(scan_id: int):
    try:
        return report_to_json(scan_id), 200, {"Content-Type": "application/json"}
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@bp.get("/api/delta")
@_api_login_required
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
@_api_login_required
def api_targets():
    return jsonify([
        {"value": t.value, "kind": t.kind, "scans": len(t.scans)}
        for t in Target.query.all()
    ])


@bp.get("/api/stats/<path:target_value>")
@_api_login_required
def api_stats(target_value: str):
    return jsonify(target_stats(target_value))


# ── Arctic pipeline ────────────────────────────────────────────────────────────

@bp.get("/north/ais")
@_api_login_required
def north_ais():
    from arctic.ais_engine import AISEngine
    try:
        bbox = _parse_bbox()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(AISEngine().fetch(bbox))


@bp.get("/north/adsb")
@_api_login_required
def north_adsb():
    from arctic.adsb_engine import ADSBEngine
    try:
        bbox = _parse_bbox()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(ADSBEngine().fetch(bbox))


@bp.get("/north/ice")
@_api_login_required
def north_ice():
    from arctic.ice_engine import IceEngine
    return jsonify(IceEngine().fetch())


@bp.get("/north/weather")
@_api_login_required
def north_weather():
    from arctic.weather_engine import WeatherEngine
    station = request.args.get("station", "CYRB")
    return jsonify(WeatherEngine().fetch(station))


@bp.get("/north/infrastructure")
@_api_login_required
def north_infra():
    from arctic.infra_engine import InfraEngine
    region = request.args.get("region", "nunavut")
    return jsonify(InfraEngine().fetch(region))


@bp.get("/north/geo")
@_api_login_required
def north_geo():
    from arctic.geo_engine import GeoEngine
    return jsonify(GeoEngine().fetch())


@bp.get("/north/satellite")
@_api_login_required
def north_satellite():
    from arctic.satellite_engine import SatelliteEngine
    days = request.args.get("days", 5, type=int)
    if days is None or not (1 <= days <= 30):
        days = 5
    aoi = request.args.get("aoi")
    eng = SatelliteEngine()
    if aoi:
        return jsonify(eng.fetch_aoi(aoi, days_back=days))
    try:
        bbox = _parse_bbox()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(eng.fetch(bbox=bbox, days_back=days))


@bp.get("/north/map")
@login_required
def north_map():
    from arctic.geo_engine import GeoEngine
    html = GeoEngine().render_map()
    return html, 200, {"Content-Type": "text/html"}
