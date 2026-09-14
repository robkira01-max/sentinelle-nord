"""Cache TTL SQLAlchemy — évite les appels API redondants."""
import hashlib
from datetime import datetime, timedelta, timezone
from models import db, CacheEntry


def _make_key(namespace: str, *parts: str) -> str:
    return hashlib.sha256("|".join((namespace, *parts)).encode()).hexdigest()


def get_cached(namespace: str, *parts: str) -> dict | None:
    try:
        key = _make_key(namespace, *parts)
        entry = CacheEntry.query.filter_by(key=key).first()
        if not entry:
            return None
        if entry.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            db.session.delete(entry)
            db.session.commit()
            return None
        return entry.value
    except RuntimeError:
        # Hors contexte Flask (thread pool) — cache miss silencieux
        return None


def set_cached(namespace: str, value: dict, ttl: int, *parts: str) -> None:
    try:
        key = _make_key(namespace, *parts)
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        entry = CacheEntry.query.filter_by(key=key).first()
        if entry:
            entry.value = value
            entry.expires_at = expires
        else:
            db.session.add(CacheEntry(key=key, value=value, expires_at=expires))
        db.session.commit()
    except RuntimeError:
        pass  # Hors contexte Flask — skip cache write
