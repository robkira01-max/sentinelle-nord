"""Comparaison de deux scans d'une même cible (delta & stats)."""
from models import db, Scan, Target


def _flatten(scan: Scan) -> dict:
    return {f"{r.source}:{r.category}": r.data for r in scan.results}


def compute_delta(scan_a_id: int, scan_b_id: int) -> dict:
    a = db.session.get(Scan, scan_a_id)  # SQLAlchemy 2.x
    b = db.session.get(Scan, scan_b_id)
    if not a or not b:
        raise ValueError("Scan introuvable")
    if a.target_id != b.target_id:
        raise ValueError("Les deux scans doivent viser la même cible")

    ra, rb = _flatten(a), _flatten(b)
    added   = {k: rb[k] for k in rb.keys() - ra.keys()}
    removed = {k: ra[k] for k in ra.keys() - rb.keys()}
    changed = {k: {"before": ra[k], "after": rb[k]}
               for k in ra.keys() & rb.keys() if ra[k] != rb[k]}

    return {
        "scan_a":    scan_a_id,
        "scan_b":    scan_b_id,
        "target":    a.target.value,
        "identical": a.hash_summary == b.hash_summary,
        "added":     added,
        "removed":   removed,
        "changed":   changed,
        "stats": {
            "sources_a": len(ra), "sources_b": len(rb),
            "added":     len(added),
            "removed":   len(removed),
            "changed":   len(changed),
        },
    }


def target_stats(target_value: str) -> dict:
    t = Target.query.filter_by(value=target_value).first()
    if not t:
        return {"target": target_value, "scans": 0}
    scans = sorted(t.scans, key=lambda s: s.started_at or 0)
    return {
        "target":          target_value,
        "scans":           len(scans),
        "first":           scans[0].started_at.isoformat() if scans else None,
        "last":            scans[-1].started_at.isoformat() if scans else None,
        "distinct_hashes": len({s.hash_summary for s in scans
                                if s.hash_summary}),
    }
