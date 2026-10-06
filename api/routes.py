"""Routes Flask — OSINT/TI + pipeline Arctique."""
from flask import Blueprint, jsonify, render_template, render_template_string, request
from flask_login import current_user, login_required

from core.aggregator import run_scan
from core.correlator import clusters_to_dict, correlate, extract_features
from extensions import limiter
from reporting.generator import build_report, report_to_json
from monitoring.delta import compute_delta, target_stats
from models import Result, Scan, Target

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
    authorized = bool(payload.get("authorized", False))
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(run_scan(target, kind, authorized=authorized))


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


# ── Corrélation d'actifs ───────────────────────────────────────────────────────

def _load_scan_features() -> list:
    """Charge les features de tous les scans terminés depuis la DB."""
    from auth.routes import require_role  # avoid circular at module level
    done_scans = Scan.query.filter_by(status="done").all()
    features = []
    for scan in done_scans:
        results = [
            {"source": r.source, "data": r.data}
            for r in Result.query.filter_by(scan_id=scan.id).all()
            if r.error is None
        ]
        feat = extract_features(scan.target.value, results)
        features.append(feat)
    # Déduplique par target (garder le plus récent = premier trouvé dans la liste)
    seen: set[str] = set()
    unique = []
    for f in features:
        if f.target not in seen:
            seen.add(f.target)
            unique.append(f)
    return unique


_CORRELATE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Corrélation d'actifs — Sentinelle_Nord</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; margin: 0; background: #f4f6f9; color: #222; }
    header { background: #1a2a44; color: #fff; padding: 1rem 2rem; }
    header h1 { margin: 0; font-size: 1.3rem; }
    header p  { margin: .2rem 0 0; font-size: .85rem; opacity: .8; }
    .container { max-width: 1100px; margin: 1.5rem auto; padding: 0 1rem; }
    .scorecard { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
    .card { background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
            box-shadow: 0 1px 4px rgba(0,0,0,.1); min-width: 130px; }
    .card .num  { font-size: 2rem; font-weight: 700; color: #1a2a44; }
    .card .lbl  { font-size: .75rem; color: #666; margin-top: .2rem; }
    .cluster { background: #fff; border-radius: 8px; margin-bottom: 1rem;
               box-shadow: 0 1px 4px rgba(0,0,0,.1); overflow: hidden; }
    .cluster-header { background: #1a2a44; color: #fff; padding: .6rem 1rem;
                      display: flex; justify-content: space-between; align-items: center; }
    .cluster-header .org { font-weight: 600; font-size: .95rem; }
    .cluster-header .cnt { font-size: .78rem; opacity: .8; }
    .cluster-body { padding: .75rem 1rem; }
    .targets { display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: .5rem; }
    .target-tag { background: #e8edf4; border-radius: 4px; padding: 2px 8px;
                  font-size: .8rem; font-family: monospace; }
    .signals { margin-top: .4rem; }
    .signal { display: inline-flex; align-items: center; gap: .3rem;
              background: #f0f4ff; border: 1px solid #c8d6f0;
              border-radius: 4px; padding: 2px 8px; font-size: .75rem;
              margin: 2px; }
    .sig-type { font-weight: 700; color: #1a2a44; }
    .sig-val  { color: #555; font-family: monospace; }
    .orphan-section h3 { color: #888; font-size: .9rem; }
    .orphan-list { display: flex; flex-wrap: wrap; gap: .4rem; }
    footer { text-align: center; color: #999; font-size: .75rem; padding: 1rem; }
    .api-link { font-size: .8rem; color: #fff; opacity: .7;
                text-decoration: none; margin-left: 1rem; }
    .api-link:hover { opacity: 1; }
  </style>
</head>
<body>
<header>
  <h1>Corrélation d'actifs par organisation</h1>
  <p>Sentinelle_Nord · Signaux : ASN, WHOIS, Nameserver, SSL SAN, IP
     <a href="/api/correlate" class="api-link">↗ JSON</a></p>
</header>
<div class="container">
  <div class="scorecard">
    <div class="card">
      <div class="num">{{ total_clusters }}</div>
      <div class="lbl">Clusters</div>
    </div>
    <div class="card">
      <div class="num">{{ total_targets }}</div>
      <div class="lbl">Cibles analysées</div>
    </div>
    <div class="card">
      <div class="num">{{ linked_targets }}</div>
      <div class="lbl">Cibles corrélées</div>
    </div>
    <div class="card">
      <div class="num">{{ multi_clusters }}</div>
      <div class="lbl">Groupes multi-cibles</div>
    </div>
  </div>

  {% for c in clusters %}
  {% if c.size > 1 %}
  <div class="cluster">
    <div class="cluster-header">
      <span class="org">{{ c.inferred_org }}</span>
      <span class="cnt">{{ c.size }} cibles · {{ c.signals|length }} signaux</span>
    </div>
    <div class="cluster-body">
      <div class="targets">
        {% for t in c.targets %}
        <span class="target-tag">{{ t }}</span>
        {% endfor %}
      </div>
      <div class="signals">
        {% for s in c.signals %}
        <span class="signal">
          <span class="sig-type">{{ s.type }}</span>
          <span class="sig-val">{{ s.value }}</span>
        </span>
        {% endfor %}
      </div>
    </div>
  </div>
  {% endif %}
  {% endfor %}

  {% set orphans = clusters | selectattr('size', 'eq', 1) | list %}
  {% if orphans %}
  <div class="orphan-section">
    <h3>Cibles sans corrélation ({{ orphans|length }})</h3>
    <div class="orphan-list">
      {% for c in orphans %}
      <span class="target-tag">{{ c.targets[0] }}</span>
      {% endfor %}
    </div>
  </div>
  {% endif %}

</div>
<footer>Sentinelle_Nord · Usage interne · Données de test fictives uniquement</footer>
</body>
</html>"""


@bp.get("/api/correlate")
@login_required
def api_correlate():
    from auth.routes import require_role as _rr
    if current_user.role not in ("admin", "analyst"):
        return jsonify({"error": "forbidden"}), 403
    features = _load_scan_features()
    clusters = correlate(features)
    return jsonify(clusters_to_dict(clusters))


@bp.get("/correlate")
@login_required
def correlate_view():
    if current_user.role not in ("admin", "analyst"):
        return jsonify({"error": "forbidden"}), 403
    features = _load_scan_features()
    clusters = correlate(features)
    data = clusters_to_dict(clusters)
    multi = sum(1 for c in data["clusters"] if c["size"] > 1)
    return render_template_string(
        _CORRELATE_HTML,
        total_clusters=data["total_clusters"],
        total_targets=data["total_targets"],
        linked_targets=data["linked_targets"],
        multi_clusters=multi,
        clusters=data["clusters"],
    )
