"""Modèles SQLAlchemy — persistance des scans, résultats et utilisateurs."""
from datetime import datetime, timezone
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

# Rôles disponibles — du plus restreint au plus permissif
ROLES = ("readonly", "analyst", "admin")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(64), unique=True, nullable=False, index=True)
    pw_hash    = db.Column(db.String(256), nullable=False)
    role       = db.Column(db.String(16), nullable=False, default="analyst")
    active     = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    def set_password(self, password: str) -> None:
        self.pw_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.pw_hash, password)

    @property
    def is_active(self) -> bool:  # type: ignore[override]
        return self.active

    def has_role(self, *roles: str) -> bool:
        return self.role in roles

    def can_scan(self) -> bool:
        return self.role in ("analyst", "admin")

    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role}>"


def _utcnow():
    return datetime.now(timezone.utc)


class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)  # domain | ip | url
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    scans = db.relationship("Scan", backref="target", lazy=True,
                            cascade="all, delete-orphan")


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    started_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status = db.Column(db.String(16), default="running")  # running|done|failed
    hash_summary = db.Column(db.String(64), nullable=True, index=True)
    results = db.relationship("Result", backref="scan", lazy=True,
                              cascade="all, delete-orphan")


class Result(db.Model):
    __tablename__ = "results"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    source = db.Column(db.String(32), nullable=False, index=True)
    category = db.Column(db.String(32), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)


class CacheEntry(db.Model):
    __tablename__ = "cache"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    value = db.Column(db.JSON, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
