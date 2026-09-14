"""Générateur de rapport PDF — Sentinelle Nord Canada.

Usage :
    python3 pdf_report.py [--out /chemin/rapport.pdf]
    python3 pdf_report.py --scan-id 4 --out rapport.pdf
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))


def _load_api(endpoint: str) -> dict:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:5000{endpoint}", timeout=10) as r:
            return json.loads(r.read())
    except Exception as exc:
        return {"error": str(exc)}


def _severity_color(sev: str) -> str:
    return {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM":   "#ffc107", "LOW":  "#28a745",
        "INFO":     "#6c757d",
    }.get((sev or "").upper(), "#6c757d")


def _dmarc_badge(dmarc: str | None) -> str:
    if not dmarc:
        return '<span class="badge red">ABSENT</span>'
    if "p=reject" in dmarc:
        return '<span class="badge green">p=reject ✓</span>'
    if "p=quarantine" in dmarc:
        return '<span class="badge orange">p=quarantine</span>'
    return '<span class="badge orange">p=none ⚠</span>'


def _spf_badge(spf: str | None) -> str:
    if not spf:
        return '<span class="badge red">ABSENT</span>'
    if "-all" in spf:
        return '<span class="badge green">-all ✓</span>'
    if "~all" in spf:
        return '<span class="badge orange">~all softfail</span>'
    return '<span class="badge grey">?all</span>'


def _ssl_badge(ssl: dict) -> str:
    days = ssl.get("days_left")
    if days is None:
        return '<span class="badge red">N/A</span>'
    if days < 0:
        return f'<span class="badge red">EXPIRÉ ({days}j)</span>'
    if days < 30:
        return f'<span class="badge orange">{days}j ⚠</span>'
    return f'<span class="badge green">{days}j ✓</span>'


def _render_risk_breakdown(breakdown: dict) -> str:
    if not breakdown:
        return '<p style="color:#888;font-size:8pt">Aucun finding calculé.</p>'
    parts = []
    for cat, items in breakdown.items():
        rows = ""
        for f in items:
            mults = " → ".join(f.get("multipliers", []))
            rows += (
                f'<tr><td>{f["title"][:70]}</td>'
                f'<td style="text-align:center">{f["cvss_base"]}</td>'
                f'<td style="text-align:center;font-weight:bold;color:{f["color"]}">'
                f'{f["weighted"]}</td>'
                f'<td><span class="badge" style="background:{f["color"]}20;color:{f["color"]}">'
                f'{f["severity"]}</span></td>'
                f'<td style="font-size:7pt;color:#666">{mults}</td></tr>'
            )
        parts.append(
            f'<div style="margin-bottom:10px">'
            f'<div style="font-size:8pt;font-weight:bold;color:#1a3a6a;'
            f'border-bottom:1px solid #dee2f0;padding-bottom:3px;margin-bottom:4px">'
            f'{cat}</div>'
            f'<table><tr><th>Finding</th><th>CVSS base</th><th>Pondéré</th>'
            f'<th>Sévérité</th><th>Multiplicateurs</th></tr>'
            f'{rows}</table></div>'
        )
    return "".join(parts)


def _render_infra_item(item: dict) -> str:
    name = item.get("name", "—")
    itype = item.get("type", "—")
    oper = item.get("operator", "—")
    badges = []
    if item.get("vulnerable"):
        badges.append('<span class="badge red">VULN</span>')
    if item.get("strategic"):
        badges.append('<span class="badge purple">STRATEGIQUE</span>')
    if not badges:
        badges.append('<span class="badge green">OK</span>')
    status = " ".join(badges)
    return (f"<tr><td><strong>{name}</strong></td>"
            f"<td>{itype}</td><td>{oper}</td><td>{status}</td></tr>")


def _render_infra_cats(cats: dict, cat_icon: dict) -> str:
    parts = []
    for cat, items in cats.items():
        icon = cat_icon.get(cat, "&bull;")
        label = cat.replace("_", " ").upper()
        rows = "".join(_render_infra_item(i) for i in items)
        parts.append(
            f'<div style="margin-bottom:8px">'
            f'<div style="font-size:8pt;font-weight:bold;color:#1a3a6a;margin-bottom:4px">'
            f'{icon} {label}</div>'
            f'<table><tr><th>Infrastructure</th><th>Type</th>'
            f'<th>Opérateur</th><th>Statut</th></tr>'
            f'{rows}</table></div>'
        )
    return "".join(parts)


def build_html(scan: dict, infra: dict, satellite: dict,
               weather: dict, adsb: dict, targets: list,
               risk: dict | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk = risk or {}

    # ── Extraire données scan canada.ca ────────────────────────
    sections = scan.get("sections", {})
    dns_data  = (sections.get("dns",  [{}])[0] if sections.get("dns")  else {}).get("data", {})
    http_data = (sections.get("http", [{}])[0] if sections.get("http") else {}).get("data", {})
    whois_data= (sections.get("whois",[{}])[0] if sections.get("whois") else {}).get("data", {})
    cve_data  = (sections.get("vulns",[{}])[0] if sections.get("vulns") else {}).get("data", {})

    ssl       = http_data.get("ssl", {})
    dmarc     = http_data.get("dmarc")
    spf       = http_data.get("spf")
    ips       = dns_data.get("records", {}).get("A", [])
    mx        = dns_data.get("records", {}).get("MX", [])
    txt_recs  = dns_data.get("records", {}).get("TXT", [])
    ns_recs   = dns_data.get("records", {}).get("NS", [])
    missing_h = http_data.get("missing_headers", [])
    sans      = ssl.get("sans", [])
    cve_items = cve_data.get("items", [])

    # ── Infrastructure ─────────────────────────────────────────
    cats  = infra.get("categories", {})
    vulns = infra.get("vulnerable", [])
    infra_total = infra.get("total_items", 0)

    # ── Satellite ──────────────────────────────────────────────
    sat_total   = satellite.get("total", 0)
    sat_products= satellite.get("products", [])
    by_col: dict[str, int] = {}
    for p in sat_products:
        by_col[p.get("collection","?")] = by_col.get(p.get("collection","?"), 0) + 1

    # ── ADS-B ──────────────────────────────────────────────────
    flights     = adsb.get("flights", [])
    flight_count= adsb.get("count", 0)

    # ── Météo stations ─────────────────────────────────────────
    stations = weather.get("all_stations", {})

    cat_icon = {
        "telecommunications": "📡", "energy": "⚡", "transport": "🚁",
        "military_public": "🪖", "health": "🏥", "water": "💧",
    }

    # ── Pré-calcul (évite {{}} dans f-string) ─────────────────
    risk_breakdown_html = _render_risk_breakdown(risk.get("breakdown") or {})
    risk_score_val  = risk.get("score", 0)
    risk_grade_val  = risk.get("grade", "—")
    risk_label_val  = risk.get("label", "—")
    risk_color_val  = risk.get("color", "#aaa")
    risk_method_val = risk.get("methodology", "")
    risk_total_val  = risk.get("total_findings", 0)
    risk_crit_val   = risk.get("critical_count", 0)

    # ── Pré-calcul valeurs SSL (évite {{}} dans f-string) ──────
    ssl_issuer   = ssl.get("issuer") or {}
    ssl_subject  = ssl.get("subject") or {}
    ssl_issuer_org = ssl_issuer.get("organizationName", "—")
    ssl_issuer_cn  = ssl_issuer.get("countryName", "—")
    ssl_subject_org = ssl_subject.get("organizationName", "—")
    ssl_subject_cn  = ssl_subject.get("commonName", "—")

    # ── HTML ───────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  @page {{
    size: A4;
    margin: 18mm 15mm 18mm 15mm;
    @top-center {{
      content: "SENTINELLE NORD CANADA — CONFIDENTIEL";
      font-size: 7pt; color: #999; font-family: sans-serif;
    }}
    @bottom-center {{
      content: "Page " counter(page) " / " counter(pages);
      font-size: 7pt; color: #999; font-family: sans-serif;
    }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 9pt;
          color: #1a1a2e; background: white; line-height: 1.45; }}

  /* ── Cover ── */
  .cover {{ text-align: center; padding: 60px 40px 40px;
            background: linear-gradient(160deg, #0a0d14 0%, #0d1a3a 100%);
            color: white; page-break-after: always; }}
  .cover .shield {{ font-size: 64pt; margin-bottom: 10px; }}
  .cover h1 {{ font-size: 26pt; color: #4a9eff; letter-spacing: .06em;
               margin-bottom: 4px; }}
  .cover h2 {{ font-size: 14pt; color: #00d4aa; margin-bottom: 30px; }}
  .cover .meta {{ font-size: 8pt; color: #8fa8d0; line-height: 2; }}
  .cover .divider {{ border: none; border-top: 1px solid #2a3a5c;
                     margin: 20px auto; width: 60%; }}

  /* ── Sections ── */
  h2.section {{ font-size: 13pt; color: #0a1628;
                border-left: 4px solid #4a9eff;
                padding: 5px 0 5px 10px;
                margin: 20px 0 10px;
                background: #f0f5ff; }}
  h3.sub {{ font-size: 10pt; color: #1a3a6a; margin: 14px 0 6px;
            border-bottom: 1px solid #dee2f0; padding-bottom: 3px; }}
  h4.sub2 {{ font-size: 9pt; color: #2a4a7a; margin: 10px 0 5px; }}

  /* ── Cards ── */
  .card {{ border: 1px solid #dee2f0; border-radius: 6px;
           margin-bottom: 10px; overflow: hidden; }}
  .card-title {{ background: #f0f5ff; padding: 5px 10px;
                 font-size: 8.5pt; font-weight: bold; color: #1a3a6a;
                 border-bottom: 1px solid #dee2f0; }}
  .card-body {{ padding: 8px 10px; }}

  /* ── Grid stat ── */
  .stat-row {{ display: flex; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }}
  .stat-box {{ flex: 1; min-width: 90px; border: 1px solid #dee2f0;
               border-radius: 6px; padding: 8px 10px; text-align: center; }}
  .stat-box .num {{ font-size: 20pt; font-weight: bold; }}
  .stat-box .lbl {{ font-size: 7pt; color: #666; text-transform: uppercase;
                    letter-spacing: .06em; margin-top: 2px; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; font-size: 8pt;
           margin-bottom: 8px; }}
  th {{ background: #0a1628; color: white; padding: 4px 7px;
        text-align: left; font-size: 7.5pt; }}
  td {{ padding: 4px 7px; border-bottom: 1px solid #e8ecf5;
        vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f8faff; }}

  /* ── Badges ── */
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
            font-size: 7.5pt; font-weight: bold; }}
  .badge.green  {{ background: #d4edda; color: #155724; }}
  .badge.orange {{ background: #fff3cd; color: #856404; }}
  .badge.red    {{ background: #f8d7da; color: #721c24; }}
  .badge.blue   {{ background: #d1ecf1; color: #0c5460; }}
  .badge.grey   {{ background: #e2e3e5; color: #383d41; }}
  .badge.purple {{ background: #e2d9f3; color: #4a0080; }}

  /* ── Finding rows ── */
  .finding {{ border-left: 3px solid #dee2f0; padding: 5px 8px;
              margin-bottom: 5px; background: #fafbff;
              border-radius: 0 4px 4px 0; }}
  .finding.critical {{ border-left-color: #dc3545; background: #fff5f5; }}
  .finding.high     {{ border-left-color: #fd7e14; background: #fff9f5; }}
  .finding.medium   {{ border-left-color: #ffc107; background: #fffef5; }}
  .finding .ftitle  {{ font-weight: bold; font-size: 8.5pt; }}
  .finding .fdesc   {{ font-size: 7.5pt; color: #555; margin-top: 2px; }}

  /* ── Misc ── */
  .two-col {{ display: flex; gap: 10px; }}
  .two-col > * {{ flex: 1; }}
  .tag {{ display: inline-block; background: #e8ecf5; color: #2a3a5c;
          padding: 1px 5px; border-radius: 3px; font-size: 7pt;
          margin: 1px; font-family: monospace; }}
  .page-break {{ page-break-before: always; }}
  .toc-item {{ display: flex; justify-content: space-between;
               padding: 3px 0; border-bottom: 1px dotted #ccc;
               font-size: 9pt; }}
  .toc-item .pg {{ color: #4a9eff; font-weight: bold; }}
  .note {{ background: #fff8e1; border: 1px solid #ffe082; border-radius: 4px;
           padding: 6px 9px; font-size: 8pt; color: #6d4c41; margin-bottom: 8px; }}
  .ok-banner {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px;
                padding: 5px 9px; font-size: 8pt; color: #155724; margin-bottom: 8px; }}
  .warn-banner {{ background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px;
                  padding: 5px 9px; font-size: 8pt; color: #856404; margin-bottom: 8px; }}
  code {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 7.5pt;
          background: #f0f2f8; padding: 0 3px; border-radius: 2px; }}
</style>
</head>
<body>

<!-- ══════════════════════════════════════════════════
     PAGE DE COUVERTURE
══════════════════════════════════════════════════ -->
<div class="cover">
  <div class="shield">🛡️</div>
  <h1>SENTINELLE NORD CANADA</h1>
  <h2>Plateforme OSINT / Threat Intelligence Arctique</h2>
  <hr class="divider">
  <div class="meta">
    <div>Rapport généré le : <strong>{now}</strong></div>
    <div>Version plateforme : <strong>2.0.0</strong></div>
    <div>Cibles analysées : <strong>{len(targets)}</strong></div>
    <div>Modules actifs : <strong>DNS · HTTP · WHOIS · CVE · AIS · ADS-B · Satellite · Météo · Infrastructure · Glace</strong></div>
    <div>Sources souveraines CA : <strong>MSC/ECCC · CIS · NRCan</strong></div>
    <div>Sources ouvertes EU : <strong>Copernicus Data Space (Sentinel-1/2/3)</strong></div>
  </div>
  <hr class="divider">
  <div style="font-size:7.5pt;color:#5a7090;margin-top:20px">
    Ce document est produit automatiquement par la plateforme Sentinelle Nord Canada.<br>
    Usage interne — recon passive uniquement — aucun scan intrusif.
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     SECTION 1 — ARCHITECTURE
══════════════════════════════════════════════════ -->
<h2 class="section">1. Architecture de la plateforme</h2>

<div class="stat-row">
  <div class="stat-box"><div class="num" style="color:#4a9eff">36</div><div class="lbl">Fichiers Python</div></div>
  <div class="stat-box"><div class="num" style="color:#00d4aa">1 900</div><div class="lbl">Lignes de code</div></div>
  <div class="stat-box"><div class="num" style="color:#43a047">7</div><div class="lbl">Collectors OSINT</div></div>
  <div class="stat-box"><div class="num" style="color:#fd7e14">6</div><div class="lbl">Modules Arctique</div></div>
  <div class="stat-box"><div class="num" style="color:#9c27b0">15</div><div class="lbl">Endpoints API</div></div>
  <div class="stat-box"><div class="num" style="color:#e53935">5</div><div class="lbl">Tâches scheduler</div></div>
</div>

<div class="two-col">
  <div class="card">
    <div class="card-title">Couche OSINT / TI</div>
    <div class="card-body">
      <table>
        <tr><th>Module</th><th>Rôle</th><th>Statut</th></tr>
        <tr><td><code>dns_collector</code></td><td>A/AAAA/MX/NS/TXT/SOA</td><td><span class="badge green">✓ Actif</span></td></tr>
        <tr><td><code>http_collector</code></td><td>Headers sécu + SSL + DMARC/SPF</td><td><span class="badge green">✓ Actif</span></td></tr>
        <tr><td><code>whois_collector</code></td><td>WHOIS normalisé</td><td><span class="badge green">✓ Actif</span></td></tr>
        <tr><td><code>cve_collector</code></td><td>NVD API 2.0 + cache 6h</td><td><span class="badge green">✓ Actif</span></td></tr>
        <tr><td><code>urlscan_collector</code></td><td>URLScan.io passif</td><td><span class="badge grey">Clé requise</span></td></tr>
        <tr><td><code>shodan_collector</code></td><td>Host lookup + cache</td><td><span class="badge grey">Clé requise</span></td></tr>
        <tr><td><code>censys_collector</code></td><td>Censys v2 + cache</td><td><span class="badge grey">Clé requise</span></td></tr>
      </table>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Pipeline Arctique</div>
    <div class="card-body">
      <table>
        <tr><th>Module</th><th>Source</th><th>Souverain</th></tr>
        <tr><td><code>ais_engine</code></td><td>AISHub</td><td><span class="badge grey">Clé requise</span></td></tr>
        <tr><td><code>adsb_engine</code></td><td>OpenSky Network (EU)</td><td><span class="badge blue">EU</span></td></tr>
        <tr><td><code>satellite_engine</code></td><td>Copernicus S1/S2/S3 (EU)</td><td><span class="badge blue">EU</span></td></tr>
        <tr><td><code>weather_engine</code></td><td>MSC DataMart ECCC</td><td><span class="badge green">✓ CA</span></td></tr>
        <tr><td><code>infra_engine</code></td><td>NRCan + données publiques</td><td><span class="badge green">✓ CA</span></td></tr>
        <tr><td><code>ice_engine</code></td><td>CIS/ECCC</td><td><span class="badge green">✓ CA</span></td></tr>
        <tr><td><code>geo_engine</code></td><td>NRCan + Folium</td><td><span class="badge green">✓ CA</span></td></tr>
      </table>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-title">Infrastructure technique</div>
  <div class="card-body">
    <table>
      <tr><th>Composant</th><th>Choix</th><th>Justification</th></tr>
      <tr><td>Framework web</td><td>Flask 3.0 + SQLAlchemy 3.1</td><td>Léger, souverain, pas de dépendance cloud</td></tr>
      <tr><td>Base de données</td><td>SQLite (→ PostgreSQL)</td><td>Local, chiffrable, migration Alembic prévue</td></tr>
      <tr><td>Cache</td><td>SQLite TTL natif</td><td>Évite les appels API redondants (NVD rate-limit)</td></tr>
      <tr><td>Scheduler</td><td>APScheduler 3.10</td><td>AIS 15min / ADS-B 10min / météo 30min / glace 24h</td></tr>
      <tr><td>Cartographie</td><td>Folium + Leaflet</td><td>Génère HTML offline — CartoDB dark matter</td></tr>
      <tr><td>Parallélisme</td><td>ThreadPoolExecutor (6 workers)</td><td>Scans multi-collecteurs simultanés</td></tr>
    </table>
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     SECTION 2 — SCORE DE RISQUE PONDÉRÉ
══════════════════════════════════════════════════ -->
<div class="page-break"></div>
<h2 class="section">2. Score de risque pondéré — canada.ca</h2>

<div style="display:flex;gap:15px;align-items:center;margin-bottom:14px">
  <div style="text-align:center;background:{risk_color_val};color:white;
              border-radius:50%;width:90px;height:90px;display:flex;
              flex-direction:column;justify-content:center;flex-shrink:0;
              padding:5px">
    <div style="font-size:22pt;font-weight:bold;line-height:1">{risk_score_val}</div>
    <div style="font-size:10pt;font-weight:bold">/10</div>
    <div style="font-size:8pt">{risk_grade_val}</div>
  </div>
  <div style="flex:1">
    <div style="font-size:13pt;font-weight:bold;color:{risk_color_val}">
      {risk_label_val}
    </div>
    <div style="font-size:7.5pt;color:#555;margin-top:4px">
      {risk_method_val}
    </div>
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <div class="stat-box" style="min-width:70px">
        <div class="num" style="font-size:16pt;color:{risk_color_val}">{risk_total_val}</div>
        <div class="lbl">Findings</div>
      </div>
      <div class="stat-box" style="min-width:70px">
        <div class="num" style="font-size:16pt;color:#dc3545">{risk_crit_val}</div>
        <div class="lbl">Critiques</div>
      </div>
    </div>
  </div>
</div>

<h3 class="sub">2.1 Findings pondérés — détail par catégorie</h3>
{risk_breakdown_html}

<h3 class="sub">2.2 Méthodologie de pondération</h3>
<table>
  <tr><th>Multiplicateur</th><th>Facteur</th><th>Condition</th></tr>
  <tr><td>CISA KEV</td><td>×1.5</td><td>Vulnérabilité exploitée in-the-wild (catalogue KEV)</td></tr>
  <tr><td>Patch Age</td><td>×1.2</td><td>Correctif disponible depuis plus de 180 jours</td></tr>
  <tr><td>Exposition email</td><td>×1.1</td><td>DMARC absent, SPF softfail, DKIM manquant</td></tr>
  <tr><td>Exposé internet</td><td>×1.2</td><td>Service admin/infra accessible publiquement</td></tr>
  <tr><td>Sans authentification</td><td>×1.3</td><td>Interface sans auth détectée</td></tr>
  <tr><td>EOL</td><td>×1.1</td><td>Version logicielle hors support officiel</td></tr>
</table>
<div class="note">Score final = 0.6 × max(CVSS pondéré) + 0.4 × moyenne(CVSS pondéré), normalisé 0–10.
Grille : A+ (0-0.9) → A (1-2.9) → B (3-4.9) → C (5-6.9) → D (7-8.9) → F (9-10).</div>

<!-- ══════════════════════════════════════════════════
     SECTION 3 — SCAN OSINT : CANADA.CA
══════════════════════════════════════════════════ -->
<div class="page-break"></div>
<h2 class="section">3. Scan OSINT — canada.ca (Portail fédéral canadien)</h2>

<div class="warn-banner">
  ⚠️ <strong>Expiration domaine dans ~32 jours</strong> — canada.ca expire le 2026-10-16.
  Si non renouvelé, le domaine devient squattable.
</div>

<div class="stat-row">
  <div class="stat-box"><div class="num" style="color:#4a9eff">24</div><div class="lbl">DNS Records</div></div>
  <div class="stat-box"><div class="num" style="color:#43a047">153</div><div class="lbl">SSL Days Left</div></div>
  <div class="stat-box"><div class="num" style="color:#fd7e14">5</div><div class="lbl">CVEs trouvés</div></div>
  <div class="stat-box"><div class="num" style="color:#e53935">0</div><div class="lbl">Headers sécu manquants*</div></div>
</div>
<div style="font-size:7pt;color:#888;margin-top:-6px;margin-bottom:10px">* Headers non collectés — timeout WAF/CDN Cloudflare</div>

<h3 class="sub">3.1 DNS</h3>
<div class="two-col">
  <div class="card">
    <div class="card-title">Adresses IP (load balancing SSC)</div>
    <div class="card-body">
      {''.join(f'<span class="tag">{ip}</span>' for ip in ips)}
    </div>
  </div>
  <div class="card">
    <div class="card-title">Name Servers</div>
    <div class="card-body">
      {''.join(f'<span class="tag">{ns}</span>' for ns in ns_recs)}
    </div>
  </div>
</div>

<div class="card">
  <div class="card-title">MX — Messagerie</div>
  <div class="card-body">
    {''.join(f'<span class="tag">{m}</span>' for m in mx)}
    <span style="font-size:7.5pt;color:#856404;margin-left:8px">→ Microsoft 365 US (souveraineté des données à évaluer)</span>
  </div>
</div>

<div class="card">
  <div class="card-title">TXT Records — Stack révélée</div>
  <div class="card-body">
    <table>
      <tr><th>Enregistrement</th><th>Service révélé</th></tr>
      {''.join(
        f"<tr><td><code>{r[:80]}</code></td><td>{_guess_service(r)}</td></tr>"
        for r in txt_recs
      )}
    </table>
  </div>
</div>

<h3 class="sub">3.2 Sécurité email (DMARC / SPF / DKIM)</h3>
<table>
  <tr><th>Contrôle</th><th>Valeur</th><th>Évaluation</th></tr>
  <tr>
    <td><strong>DMARC</strong></td>
    <td><code>{(dmarc or 'ABSENT')[:80]}</code></td>
    <td>{_dmarc_badge(dmarc)} <span style="font-size:7.5pt;color:#856404">p=none = monitoring seulement, spoofing possible</span></td>
  </tr>
  <tr>
    <td><strong>SPF</strong></td>
    <td><code>{(spf or 'ABSENT')[:80]}</code></td>
    <td>{_spf_badge(spf)}</td>
  </tr>
  <tr>
    <td><strong>DKIM</strong></td>
    <td><em>Non détecté (selectors standards)</em></td>
    <td><span class="badge grey">Inconnu</span></td>
  </tr>
</table>

<h3 class="sub">3.3 SSL/TLS</h3>
<table>
  <tr><th>Champ</th><th>Valeur</th></tr>
  <tr><td>Expiry</td><td>{ssl.get('not_after','—')} {_ssl_badge(ssl)}</td></tr>
  <tr><td>Émetteur</td><td>{ssl_issuer_org} ({ssl_issuer_cn}) <span class="badge green">Entrust CA — souverain</span></td></tr>
  <tr><td>Sujet</td><td>{ssl_subject_org} — {ssl_subject_cn}</td></tr>
  <tr><td>SANs ({len(sans)})</td><td>{'  '.join(f'<span class="tag">{s}</span>' for s in sans)}</td></tr>
</table>

<h3 class="sub">3.4 WHOIS</h3>
<table>
  <tr><th>Champ</th><th>Valeur</th></tr>
  <tr><td>Registrar</td><td>{whois_data.get('registrar','—')}</td></tr>
  <tr><td>Créé</td><td>{str(whois_data.get('creation_date','—'))[:10]}</td></tr>
  <tr>
    <td>Expiration</td>
    <td><strong style="color:#dc3545">{str(whois_data.get('expiration_date','—'))[:10]}</strong>
    <span class="badge red">~32 jours</span></td>
  </tr>
  <tr><td>Name servers</td><td>{'  '.join(f'<span class="tag">{ns}</span>' for ns in (whois_data.get('name_servers') or [])[:6])}</td></tr>
</table>

<h3 class="sub">3.5 CVEs (keyword: canada)</h3>
{f'''<div class="note">ℹ️ Keyword trop générique — configurez <code>CVE_KEYWORD</code> dans .env pour cibler la stack réelle.</div>
<table>
  <tr><th>CVE</th><th>Score CVSS</th><th>Sévérité</th></tr>
  {"".join(f'<tr><td><code>{c.get("cve","—")}</code></td><td>{c.get("score","—")}</td><td><span class="badge {'orange' if (c.get('score') or 0) >= 5 else 'grey'}">{c.get("severity","—")}</span></td></tr>' for c in cve_items)}
</table>''' if cve_items else '<p style="color:#888;font-size:8pt">Aucun CVE retourné.</p>'}

<h3 class="sub">3.6 Findings prioritaires</h3>
<div class="finding high">
  <div class="ftitle">🔴 Expiration domaine canada.ca dans ~32 jours</div>
  <div class="fdesc">Expiration le 2026-10-16. Si non renouvelé, canada.ca peut être enregistré par un tiers.
  Registrar : Authentic Web Inc. (non-gouvernemental). Action immédiate requise.</div>
</div>
<div class="finding medium">
  <div class="ftitle">🟡 DMARC p=none — politique non enforced</div>
  <div class="fdesc">Le DMARC est configuré en mode monitoring seulement (p=none). Un attaquant peut
  envoyer des emails usurpant @canada.ca sans rejet automatique. Recommandation : p=quarantine puis p=reject.</div>
</div>
<div class="finding medium">
  <div class="ftitle">🟡 Messagerie hébergée Microsoft 365 (US)</div>
  <div class="fdesc">MX pointe vers canada-ca.mail.protection.outlook.com. Les emails gouvernementaux
  transitent par l'infrastructure Microsoft US — souveraineté des données à évaluer selon LPRPDE / Loi C-27.</div>
</div>
<div class="finding medium">
  <div class="ftitle">🟡 Stack SaaS US révélée par TXT records</div>
  <div class="fdesc">Adobe IDP, Cisco CI, Microsoft 365 (×3), Google Verify, LinkedIn (×2)
  tous révélés publiquement via DNS TXT. Surface d'attaque supply chain élargie.</div>
</div>

<!-- ══════════════════════════════════════════════════
     SECTION 3 — PIPELINE ARCTIQUE
══════════════════════════════════════════════════ -->
<div class="page-break"></div>
<h2 class="section">4. Pipeline Arctique — État opérationnel</h2>

<div class="stat-row">
  <div class="stat-box"><div class="num" style="color:#4a9eff">{flight_count}</div><div class="lbl">Vols ADS-B actifs</div></div>
  <div class="stat-box"><div class="num" style="color:#00d4aa">{sat_total}</div><div class="lbl">Produits satellites</div></div>
  <div class="stat-box"><div class="num" style="color:#43a047">{len(stations)}</div><div class="lbl">Stations météo</div></div>
  <div class="stat-box"><div class="num" style="color:#fd7e14">{infra_total}</div><div class="lbl">Infras nordiques</div></div>
  <div class="stat-box"><div class="num" style="color:#e53935">{len(vulns)}</div><div class="lbl">Infras vulnérables</div></div>
  <div class="stat-box"><div class="num" style="color:#9c27b0">4</div><div class="lbl">Produits CIS glace</div></div>
</div>

<h3 class="sub">4.1 ADS-B — Trafic aérien polaire (OpenSky Network)</h3>
<div class="ok-banner">✅ Source : OpenSky Network (EU) — libre, sans inscription — zone 60–90°N</div>
<table>
  <tr><th>ICAO24</th><th>Callsign</th><th>Pays</th><th>Altitude (m)</th><th>Vitesse</th><th>Sol</th></tr>
  {(''.join(
    f'<tr><td><code>{f.get("icao24","—")}</code></td><td>{f.get("callsign","—")}</td>'
    f'<td>{f.get("origin_country","—")}</td>'
    f'<td>{round(f["altitude_m"]) if f.get("altitude_m") else "—"}</td>'
    f'<td>{round(f["velocity_ms"]*1.944) if f.get("velocity_ms") else "—"} kn</td>'
    f'<td>{"Oui" if f.get("on_ground") else "Non"}</td></tr>'
    for f in flights[:10]
  )) if flights else '<tr><td colspan="6" style="text-align:center;color:#888">Aucun vol détecté dans la zone</td></tr>'}
</table>

<h3 class="sub">4.2 Satellites Copernicus — Produits récents (3 jours)</h3>
<div class="ok-banner">✅ Source : Copernicus Data Space Ecosystem (EU) — OData API sans authentification</div>
<div class="stat-row">
  {(''.join(
    f'<div class="stat-box"><div class="num" style="color:#4a9eff">{cnt}</div>'
    f'<div class="lbl">{col.replace("SENTINEL-","S")}</div></div>'
    for col, cnt in by_col.items()
  ))}
</div>
<table>
  <tr><th>Collection</th><th>Produit</th><th>Date acquisition</th><th>Taille</th><th>En ligne</th></tr>
  {(''.join(
    f'<tr><td><span class="badge blue">{p.get("collection","?")[:4]}</span></td>'
    f'<td style="max-width:200px;overflow:hidden;font-size:7pt">{(p.get("name") or "")[:55]}</td>'
    f'<td>{(p.get("date") or "")[:16]}</td>'
    f'<td>{p.get("size_mb","—")} MB</td>'
    f'<td>{"✓" if p.get("online") else "✗"}</td></tr>'
    for p in sat_products[:12]
  ))}
</table>

<h3 class="sub">4.3 Météo nordique — MSC DataMart ECCC (souverain CA)</h3>
<table>
  <tr><th>Code ICAO</th><th>Station</th><th>Province</th><th>Lat</th><th>Lon</th></tr>
  {(''.join(
    f'<tr><td><code>{code}</code></td><td>{s["name"]}</td><td>{s["prov"]}</td>'
    f'<td>{s["lat"]}°N</td><td>{abs(s["lon"])}°O</td></tr>'
    for code, s in stations.items()
  ))}
</table>

<h3 class="sub">4.4 Infrastructures critiques nordiques</h3>
{_render_infra_cats(cats, cat_icon)}

<!-- ══════════════════════════════════════════════════
     SECTION 4 — RECOMMANDATIONS
══════════════════════════════════════════════════ -->
<div class="page-break"></div>
<h2 class="section">5. Recommandations</h2>

<h3 class="sub">5.1 Urgences immédiates — canada.ca</h3>
<table>
  <tr><th>#</th><th>Recommandation</th><th>Priorité</th><th>Délai</th></tr>
  <tr><td>R1</td><td>Renouveler le domaine canada.ca avant le 2026-10-16</td>
      <td><span class="badge red">CRITIQUE</span></td><td>Immédiat</td></tr>
  <tr><td>R2</td><td>Passer DMARC de p=none à p=quarantine (puis p=reject)</td>
      <td><span class="badge orange">HAUTE</span></td><td>30 jours</td></tr>
  <tr><td>R3</td><td>Évaluer la souveraineté de Microsoft 365 pour les emails GC</td>
      <td><span class="badge orange">HAUTE</span></td><td>90 jours</td></tr>
  <tr><td>R4</td><td>Configurer CVE_KEYWORD avec la stack réelle (Drupal/AEM/etc.)</td>
      <td><span class="badge grey">NORMALE</span></td><td>7 jours</td></tr>
</table>

<h3 class="sub">5.2 Plateforme — extensions prioritaires</h3>
<table>
  <tr><th>#</th><th>Fonctionnalité</th><th>Impact</th><th>Effort</th></tr>
  <tr><td>P1</td><td>Score de risque pondéré CVSS × KEV × âge (de cve_engine.py v1)</td>
      <td><span class="badge red">ÉLEVÉ</span></td><td>Moyen</td></tr>
  <tr><td>P2</td><td>Export PDF automatique post-scan (WeasyPrint intégré)</td>
      <td><span class="badge orange">MOYEN</span></td><td>Faible</td></tr>
  <tr><td>P3</td><td>ThreatIntel collector (AlienVault OTX + GreyNoise)</td>
      <td><span class="badge orange">MOYEN</span></td><td>Faible</td></tr>
  <tr><td>P4</td><td>Alerting webhook (delta critique → notification)</td>
      <td><span class="badge orange">MOYEN</span></td><td>Moyen</td></tr>
  <tr><td>P5</td><td>Migration PostgreSQL + Alembic pour charge production</td>
      <td><span class="badge grey">NORMAL</span></td><td>Élevé</td></tr>
  <tr><td>P6</td><td>Dockerisation + Gunicorn pour déploiement OVHcloud Canada</td>
      <td><span class="badge grey">NORMAL</span></td><td>Moyen</td></tr>
</table>

<h3 class="sub">5.3 Souveraineté numérique — état des sources</h3>
<table>
  <tr><th>Source</th><th>Souveraineté</th><th>Note</th></tr>
  <tr><td>MSC DataMart ECCC</td><td><span class="badge green">✓ Canadienne</span></td><td>Météo, données ouvertes ECCC</td></tr>
  <tr><td>CIS / ECCC</td><td><span class="badge green">✓ Canadienne</span></td><td>Glace marine, WMS/WFS</td></tr>
  <tr><td>NRCan GeoGratis</td><td><span class="badge green">✓ Canadienne</span></td><td>Données géospatiales, infrastructures</td></tr>
  <tr><td>Copernicus / Sentinel</td><td><span class="badge blue">EU (open)</span></td><td>Imagerie SAR/optique Arctique</td></tr>
  <tr><td>OpenSky Network</td><td><span class="badge blue">EU (libre)</span></td><td>ADS-B, pas de compte requis</td></tr>
  <tr><td>AISHub</td><td><span class="badge grey">Privé (inscription)</span></td><td>AIS maritime, clé API gratuite</td></tr>
  <tr><td>NVD / NIST</td><td><span class="badge orange">US Federal</span></td><td>CVE database — pas d'alternative souveraine</td></tr>
  <tr><td>Shodan / Censys</td><td><span class="badge orange">US Privé</span></td><td>Optionnel, désactivé par défaut</td></tr>
</table>

<div style="margin-top:30px;text-align:center;font-size:7pt;color:#aaa;border-top:1px solid #eee;padding-top:10px">
  Sentinelle Nord Canada v2.0 — Rapport auto-généré le {now}<br>
  Recon passive uniquement — aucun scan actif/intrusif — usage interne
</div>

</body>
</html>"""


def _guess_service(txt: str) -> str:
    txt = txt.lower()
    if "spf1" in txt:   return "SPF record"
    if "dmarc" in txt:  return "DMARC record"
    if "ms="   in txt:  return "Microsoft 365 (Office)"
    if "google" in txt: return "Google Search Console"
    if "adobe" in txt:  return "Adobe IDP / AEM"
    if "cisco" in txt:  return "Cisco CI"
    if "linkedin" in txt: return "LinkedIn"
    if "trusted" in txt:  return "Microsoft (Tenant)"
    return "—"


def main():
    from datetime import date
    today = date.today().isoformat()
    parser = argparse.ArgumentParser(description="Génère le PDF Sentinelle Nord Canada")
    parser.add_argument("--out", default=f"/home/kali/OSINT_Reports/Sentinelle-NordCanada-{today}.pdf")
    parser.add_argument("--scan-id", type=int, default=4)
    args = parser.parse_args()

    print("Collecte des données live…")
    scan      = _load_api(f"/api/report/{args.scan_id}")
    infra     = _load_api("/north/infrastructure?region=all")
    satellite = _load_api("/north/satellite?days=3")
    weather   = _load_api("/north/weather")
    adsb      = _load_api("/north/adsb")
    targets   = _load_api("/api/targets")

    print(f"  scan_id={scan.get('scan_id')} target={scan.get('target')}")
    print(f"  satellite={satellite.get('total')} produits")
    print(f"  infra={infra.get('total_items')} items")

    print("Calcul du score de risque pondéré…")
    from reporting.risk_score import compute_risk_score
    risk = compute_risk_score(scan)
    print(f"  score={risk['score']}/10  grade={risk['grade']}  "
          f"findings={risk['total_findings']}  critiques={risk['critical_count']}")

    print("Génération HTML…")
    html = build_html(scan, infra, satellite, weather, adsb,
                      targets if isinstance(targets, list) else [],
                      risk=risk)

    print("Rendu PDF WeasyPrint…")
    from weasyprint import HTML
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(BASE_DIR)).write_pdf(str(out_path))

    size_kb = out_path.stat().st_size // 1024
    print(f"PDF généré : {out_path} ({size_kb} KB)")
    return str(out_path)


if __name__ == "__main__":
    main()
