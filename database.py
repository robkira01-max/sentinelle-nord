"""Helpers DB — initialisation et accès haut niveau."""
from datetime import datetime, timezone
from models import db, Target, Scan, Result


def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()


def get_or_create_target(value: str, kind: str) -> Target:
    t = Target.query.filter_by(value=value).first()
    if not t:
        t = Target(value=value, kind=kind)
        db.session.add(t)
        db.session.commit()
    return t


def create_scan(target: Target) -> Scan:
    s = Scan(target_id=target.id, status="running")
    db.session.add(s)
    db.session.commit()
    return s


def finalize_scan(scan: Scan, status: str = "done",
                  hash_summary: str | None = None) -> None:
    scan.status = status
    scan.finished_at = datetime.now(timezone.utc)
    scan.hash_summary = hash_summary
    db.session.commit()


def store_results(scan: Scan, results: list[dict]) -> None:
    for r in results:
        db.session.add(Result(
            scan_id=scan.id,
            source=r.get("source", "unknown"),
            category=r.get("category", "misc"),
            data=r.get("data", {}),
            error=r.get("error"),
        ))
    db.session.commit()
