"""Blueprint /compliance — tableau de bord CPCSC Niveau 1."""
from __future__ import annotations

import io
from datetime import date

from flask import Blueprint, jsonify, render_template_string, Response
from flask_login import login_required

from auth.routes import require_role
from compliance.cpcsc_l1 import CONTROLS, as_dict, compute_score, _STATUS_LABEL

compliance_bp = Blueprint("compliance", __name__, url_prefix="/compliance")

# Couleurs par statut pour le badge HTML
_STATUS_COLOR = {
    "IMPLEMENTED":     "#2d9e5a",
    "PARTIAL":         "#e6a817",
    "PROCEDURAL":      "#5b8dd9",
    "NOT_IMPLEMENTED": "#d9534f",
}

_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CPCSC Niveau 1 — Auto-évaluation</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; margin: 0; background: #f4f6f9; color: #222; }
    header { background: #1a2a44; color: #fff; padding: 1rem 2rem; }
    header h1 { margin: 0; font-size: 1.3rem; }
    header p  { margin: .2rem 0 0; font-size: .85rem; opacity: .8; }
    .container { max-width: 1100px; margin: 1.5rem auto; padding: 0 1rem; }
    .scorecard { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
    .card { background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
            box-shadow: 0 1px 4px rgba(0,0,0,.1); min-width: 140px; }
    .card .num  { font-size: 2rem; font-weight: 700; }
    .card .lbl  { font-size: .75rem; color: #666; margin-top: .2rem; }
    .score-pct { font-size: 2.5rem !important; color: {{ score_color }}; }
    table { width: 100%; border-collapse: collapse; background: #fff;
            border-radius: 8px; overflow: hidden;
            box-shadow: 0 1px 4px rgba(0,0,0,.1); margin-bottom: 2rem; }
    th { background: #1a2a44; color: #fff; padding: .6rem .8rem;
         text-align: left; font-size: .8rem; }
    td { padding: .55rem .8rem; border-bottom: 1px solid #eee;
         font-size: .82rem; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f9f9f9; }
    .badge { display: inline-block; border-radius: 4px; padding: 2px 8px;
             font-size: .72rem; font-weight: 600; color: #fff; }
    .domain-header td { background: #e8edf4; font-weight: 700;
                        font-size: .78rem; color: #1a2a44; }
    .gap { color: #b84f4f; font-style: italic; }
    .evidence { color: #444; }
    .refs { color: #777; font-size: .75rem; }
    .export-btn { background: #1a2a44; color: #fff; border: none;
                  padding: .5rem 1.2rem; border-radius: 6px; cursor: pointer;
                  font-size: .85rem; text-decoration: none; }
    .export-btn:hover { background: #2e4a7a; }
    footer { text-align: center; color: #999; font-size: .75rem;
             padding: 1rem; margin-top: 1rem; }
  </style>
</head>
<body>
<header>
  <h1>CPCSC Niveau 1 — Auto-évaluation · Sentinelle_Nord</h1>
  <p>{{ framework }} &nbsp;·&nbsp; {{ assessment_date }} &nbsp;·&nbsp;
     <a href="/compliance/cpcsc/export" class="export-btn">Exporter PDF</a></p>
</header>
<div class="container">

  <div class="scorecard">
    <div class="card">
      <div class="num score-pct">{{ score_pct }}%</div>
      <div class="lbl">Score de conformité</div>
    </div>
    {% for status, label in status_labels.items() %}
    <div class="card">
      <div class="num" style="color:{{ status_colors[status] }}">{{ counts[status] }}</div>
      <div class="lbl">{{ label }}</div>
    </div>
    {% endfor %}
    <div class="card">
      <div class="num">{{ total }}</div>
      <div class="lbl">Contrôles total</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th style="width:110px">ID</th>
        <th>Titre</th>
        <th style="width:115px">Statut</th>
        <th>Preuve / Lacune</th>
        <th style="width:60px">Prio</th>
      </tr>
    </thead>
    <tbody>
    {% for domain, items in domains.items() %}
      <tr class="domain-header"><td colspan="5">{{ domain }}</td></tr>
      {% for c in items %}
      <tr>
        <td><code>{{ c.id }}</code></td>
        <td>{{ c.title }}</td>
        <td>
          <span class="badge"
                style="background:{{ status_colors[c.status] }}">
            {{ c.status_label }}
          </span>
        </td>
        <td>
          <span class="evidence">{{ c.evidence }}</span>
          {% if c.gap %}
          <br><span class="gap">⚠ {{ c.gap }}</span>
          {% endif %}
          {% if c.references %}
          <br><span class="refs">→ {{ c.references|join(', ') }}</span>
          {% endif %}
        </td>
        <td>{{ c.priority }}</td>
      </tr>
      {% endfor %}
    {% endfor %}
    </tbody>
  </table>

</div>
<footer>Sentinelle_Nord · Usage interne · Données de test fictives uniquement</footer>
</body>
</html>"""


def _score_color(pct: float) -> str:
    if pct >= 75:
        return "#2d9e5a"
    if pct >= 50:
        return "#e6a817"
    return "#d9534f"


@compliance_bp.route("/cpcsc")
@require_role("admin", "analyst")
def cpcsc_dashboard():
    data = as_dict()
    summary = data["summary"]
    return render_template_string(
        _HTML,
        score_pct=summary["score_pct"],
        score_color=_score_color(summary["score_pct"]),
        total=summary["total"],
        counts=summary["counts"],
        framework=summary["framework"],
        assessment_date=summary["assessment_date"],
        domains=data["domains"],
        status_labels=_STATUS_LABEL,
        status_colors=_STATUS_COLOR,
    )


@compliance_bp.route("/cpcsc.json")
@require_role("admin", "analyst")
def cpcsc_json():
    return jsonify(as_dict())


@compliance_bp.route("/cpcsc/export")
@require_role("admin", "analyst")
def cpcsc_export():
    try:
        from weasyprint import HTML as WP_HTML  # type: ignore[import]
    except ImportError:
        return "WeasyPrint non disponible sur ce serveur.", 503

    data = as_dict()
    summary = data["summary"]
    html_str = render_template_string(
        _HTML,
        score_pct=summary["score_pct"],
        score_color=_score_color(summary["score_pct"]),
        total=summary["total"],
        counts=summary["counts"],
        framework=summary["framework"],
        assessment_date=summary["assessment_date"],
        domains=data["domains"],
        status_labels=_STATUS_LABEL,
        status_colors=_STATUS_COLOR,
    )
    pdf_bytes = WP_HTML(string=html_str).write_pdf()
    filename = f"cpcsc_niveau1_{date.today().isoformat()}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
