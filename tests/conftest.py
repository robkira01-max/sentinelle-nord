"""Fixtures pytest — Sentinelle Nord Flask app."""
import os
import pytest
from sqlalchemy.pool import StaticPool

os.environ.setdefault("SCHEDULER_ENABLED", "false")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "testing")

from app import create_app          # noqa: E402 — env must be set first
from models import db as _db, User  # noqa: E402

_TEST_CONFIG = {
    "TESTING": True,
    "WTF_CSRF_ENABLED": False,
    "RATELIMIT_ENABLED": False,
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_ENGINE_OPTIONS": {
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    },
}


@pytest.fixture(scope="session")
def app():
    flask_app = create_app(test_config=_TEST_CONFIG)
    return flask_app


@pytest.fixture()
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app, db):
    return app.test_client()


# ── Utilisateurs de test ──────────────────────────────────────────────────────

@pytest.fixture()
def admin_user(db):
    u = User(username="admin_test", role="admin")
    u.set_password("AdminPassword2026!")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def analyst_user(db):
    u = User(username="analyst_test", role="analyst")
    u.set_password("AnalystPassword2026!")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def readonly_user(db):
    u = User(username="readonly_test", role="readonly")
    u.set_password("ReadonlyPassword2026!")
    db.session.add(u)
    db.session.commit()
    return u


# ── Clients authentifiés ──────────────────────────────────────────────────────

def _login(client, username: str, password: str):
    return client.post("/auth/login", data={
        "username": username,
        "password": password,
    }, follow_redirects=False)


@pytest.fixture()
def admin_client(client, admin_user):
    _login(client, "admin_test", "AdminPassword2026!")
    return client


@pytest.fixture()
def analyst_client(client, analyst_user):
    _login(client, "analyst_test", "AnalystPassword2026!")
    return client


@pytest.fixture()
def readonly_client(client, readonly_user):
    _login(client, "readonly_test", "ReadonlyPassword2026!")
    return client
