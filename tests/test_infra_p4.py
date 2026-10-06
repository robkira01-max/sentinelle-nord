"""Tests P4 — PostgreSQL / Docker / gunicorn infrastructure."""
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# config.py — DATABASE_URL conversion
# ---------------------------------------------------------------------------

class TestDatabaseUrlConversion:
    """Verify that postgres:// is rewritten to postgresql:// (SQLAlchemy 2.x)."""

    def _reload_config(self, raw_url: str) -> str:
        """Reload config module with a custom DATABASE_URL env var."""
        with patch.dict(os.environ, {"DATABASE_URL": raw_url}):
            if "config" in sys.modules:
                mod = importlib.reload(sys.modules["config"])
            else:
                mod = importlib.import_module("config")
            return mod.Config.DATABASE_URL

    def test_postgres_scheme_rewritten(self):
        url = self._reload_config("postgres://user:pass@db:5432/mydb")
        assert url.startswith("postgresql://")

    def test_postgresql_scheme_unchanged(self):
        url = self._reload_config("postgresql://user:pass@db:5432/mydb")
        assert url == "postgresql://user:pass@db:5432/mydb"

    def test_sqlite_scheme_unchanged(self):
        url = self._reload_config("sqlite:///osint.db")
        assert url == "sqlite:///osint.db"

    def test_sqlite_memory_unchanged(self):
        url = self._reload_config("sqlite:///:memory:")
        assert url == "sqlite:///:memory:"

    def test_rewrite_preserves_credentials_and_path(self):
        raw = "postgres://sentinelle:secret@db:5432/sentinelle"
        url = self._reload_config(raw)
        assert url == "postgresql://sentinelle:secret@db:5432/sentinelle"

    def test_only_first_occurrence_replaced(self):
        """Edge case: scheme only replaced at the start, not elsewhere."""
        raw = "postgres://host/db?options=postgres://ignored"
        url = self._reload_config(raw)
        assert url.startswith("postgresql://")
        # The rest of the URL should be intact
        assert "postgres://ignored" in url


# ---------------------------------------------------------------------------
# wsgi.py — entry-point for gunicorn
# ---------------------------------------------------------------------------

class TestWsgiEntryPoint:
    """wsgi.py must expose a WSGI-callable `app` attribute."""

    def test_wsgi_imports_without_error(self):
        if "wsgi" in sys.modules:
            del sys.modules["wsgi"]
        # Ensure test environment variables are set
        with patch.dict(os.environ, {
            "DATABASE_URL": "sqlite:///:memory:",
            "FLASK_SECRET_KEY": "test-wsgi-key",
            "SCHEDULER_ENABLED": "false",
        }):
            import wsgi as wsgi_mod  # noqa: PLC0415
            assert wsgi_mod is not None

    def test_wsgi_app_is_callable(self):
        if "wsgi" in sys.modules:
            del sys.modules["wsgi"]
        with patch.dict(os.environ, {
            "DATABASE_URL": "sqlite:///:memory:",
            "FLASK_SECRET_KEY": "test-wsgi-key",
            "SCHEDULER_ENABLED": "false",
        }):
            import wsgi as wsgi_mod  # noqa: PLC0415
            assert callable(wsgi_mod.app)

    def test_wsgi_app_has_flask_interface(self):
        """The object must have a Flask-like test_client method."""
        if "wsgi" in sys.modules:
            del sys.modules["wsgi"]
        with patch.dict(os.environ, {
            "DATABASE_URL": "sqlite:///:memory:",
            "FLASK_SECRET_KEY": "test-wsgi-key",
            "SCHEDULER_ENABLED": "false",
        }):
            import wsgi as wsgi_mod  # noqa: PLC0415
            assert hasattr(wsgi_mod.app, "test_client")


# ---------------------------------------------------------------------------
# gunicorn.conf.py — production configuration
# ---------------------------------------------------------------------------

class TestGunicornConfig:
    """gunicorn.conf.py must define required production settings."""

    @pytest.fixture(autouse=True)
    def load_gunicorn_conf(self):
        cfg_path = PROJECT_ROOT / "gunicorn.conf.py"
        self._cfg = {}
        exec(compile(cfg_path.read_text(), str(cfg_path), "exec"), self._cfg)  # noqa: S102

    def test_workers_defined(self):
        assert "workers" in self._cfg
        assert isinstance(self._cfg["workers"], int)
        assert self._cfg["workers"] >= 1

    def test_workers_reasonable_upper_bound(self):
        # Should not exceed 32 workers for any realistic server
        assert self._cfg["workers"] <= 32

    def test_bind_defined(self):
        assert "bind" in self._cfg
        assert isinstance(self._cfg["bind"], str)

    def test_bind_exposes_all_interfaces(self):
        assert self._cfg["bind"].startswith("0.0.0.0:")

    def test_timeout_defined_and_positive(self):
        assert "timeout" in self._cfg
        assert isinstance(self._cfg["timeout"], int)
        assert self._cfg["timeout"] > 0

    def test_accesslog_to_stdout(self):
        assert self._cfg.get("accesslog") == "-"

    def test_errorlog_to_stderr(self):
        assert self._cfg.get("errorlog") == "-"

    def test_limit_request_line_set(self):
        assert "limit_request_line" in self._cfg
        assert self._cfg["limit_request_line"] <= 8190  # gunicorn max

    def test_limit_request_fields_set(self):
        assert "limit_request_fields" in self._cfg
        assert self._cfg["limit_request_fields"] <= 32768


# ---------------------------------------------------------------------------
# docker-compose.yml — structure validation
# ---------------------------------------------------------------------------

class TestDockerCompose:
    """Verify docker-compose.yml has required services, healthcheck, and volumes."""

    @pytest.fixture(autouse=True)
    def load_compose(self):
        compose_path = PROJECT_ROOT / "docker-compose.yml"
        with compose_path.open() as fh:
            self._compose = yaml.safe_load(fh)

    def test_services_key_present(self):
        assert "services" in self._compose

    def test_db_service_present(self):
        assert "db" in self._compose["services"]

    def test_app_service_present(self):
        assert "app" in self._compose["services"]

    def test_db_uses_postgres_image(self):
        image = self._compose["services"]["db"].get("image", "")
        assert "postgres" in image

    def test_db_has_healthcheck(self):
        db = self._compose["services"]["db"]
        assert "healthcheck" in db
        hc = db["healthcheck"]
        assert "test" in hc

    def test_db_healthcheck_uses_pg_isready(self):
        hc = self._compose["services"]["db"]["healthcheck"]
        test_cmd = " ".join(hc["test"]) if isinstance(hc["test"], list) else hc["test"]
        assert "pg_isready" in test_cmd

    def test_app_depends_on_db(self):
        app = self._compose["services"]["app"]
        assert "depends_on" in app
        depends = app["depends_on"]
        # Can be a list or a dict (with condition)
        if isinstance(depends, dict):
            assert "db" in depends
        else:
            assert "db" in depends

    def test_app_depends_on_db_healthy(self):
        depends = self._compose["services"]["app"]["depends_on"]
        if isinstance(depends, dict):
            assert depends.get("db", {}).get("condition") == "service_healthy"

    def test_app_exposes_port(self):
        app = self._compose["services"]["app"]
        assert "ports" in app
        assert len(app["ports"]) >= 1

    def test_pgdata_volume_defined(self):
        assert "volumes" in self._compose
        assert "pgdata" in self._compose["volumes"]

    def test_postgres_password_required(self):
        db_env = self._compose["services"]["db"].get("environment", {})
        pw_value = (
            db_env.get("POSTGRES_PASSWORD", "")
            if isinstance(db_env, dict)
            else ""
        )
        # Must use ${POSTGRES_PASSWORD:?...} (fail-fast) not a hardcoded value
        assert "${POSTGRES_PASSWORD" in str(pw_value)

    def test_no_hardcoded_password(self):
        raw = (PROJECT_ROOT / "docker-compose.yml").read_text()
        # Ensure no obvious literal password
        assert "password:" not in raw.lower() or "POSTGRES_PASSWORD" in raw
