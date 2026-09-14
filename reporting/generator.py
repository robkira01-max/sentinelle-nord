"""Génération de rapports JSON structurés à partir d'un scan."""
import json
from datetime import datetime, timezone
from models import db, Scan, Result


def build_report(scan_id: int) -> dict:
    scan = db.session.get(Scan, scan_id)  # SQLAlchemy 2.x
    if not scan:
        raise ValueError(f"Scan {scan_id} introuvable")

    results = Result.query.filter_by(scan_id=scan_id).all()
    return {
        "scan_id":     scan.id,
        "target":      scan.target.value,
        "kind":        scan.target.kind,
        "status":      scan.status,
        "started_at":  scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "hash":        scan.hash_summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sections":    _group_sections(results),
    }


def _group_sections(results: list[Result]) -> dict:
    sections: dict[str, list] = {}
    for r in results:
        sections.setdefault(r.category, []).append({
            "source": r.source,
            "data":   r.data,
            "error":  r.error,
        })
    return sections


def report_to_json(scan_id: int) -> str:
    return json.dumps(build_report(scan_id), indent=2, default=str)
