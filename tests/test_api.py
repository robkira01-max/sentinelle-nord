"""Tests — API OSINT/TI (scan, report, delta, stats)."""
import json
from unittest.mock import patch, MagicMock

import pytest

from models import db as _db, Target, Scan, Result


# ── Dashboard ──────────────────────────────────────────────────────────────────

class TestDashboard:
    def test_dashboard_requires_auth(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 302

    def test_dashboard_accessible_to_admin(self, admin_client):
        r = admin_client.get("/")
        assert r.status_code == 200

    def test_dashboard_accessible_to_analyst(self, analyst_client):
        r = analyst_client.get("/")
        assert r.status_code == 200


# ── /api/scan ─────────────────────────────────────────────────────────────────

_MOCK_SCAN_RESULT = {
    "scan_id": 1,
    "target": "example.com",
    "kind": "domain",
    "hash": "abc123",
    "results": [
        {"source": "dns", "category": "dns",
         "data": {"records": {"A": ["1.2.3.4"]}, "record_count": 1}, "error": None}
    ],
}


class TestScanEndpoint:
    def test_scan_requires_auth(self, client):
        r = client.post("/api/scan",
                        data=json.dumps({"target": "example.com"}),
                        content_type="application/json")
        assert r.status_code == 401

    def test_readonly_user_cannot_scan(self, readonly_client):
        r = readonly_client.post("/api/scan",
                                  data=json.dumps({"target": "example.com"}),
                                  content_type="application/json")
        assert r.status_code == 403

    def test_scan_requires_target(self, analyst_client):
        r = analyst_client.post("/api/scan",
                                 data=json.dumps({}),
                                 content_type="application/json")
        assert r.status_code == 400
        assert r.get_json()["error"] == "target required"

    @patch("api.routes.run_scan", return_value=_MOCK_SCAN_RESULT)
    def test_analyst_can_scan(self, mock_scan, analyst_client):
        r = analyst_client.post("/api/scan",
                                 data=json.dumps({"target": "example.com"}),
                                 content_type="application/json")
        assert r.status_code == 200
        data = r.get_json()
        assert data["target"] == "example.com"
        mock_scan.assert_called_once_with("example.com", "domain")

    @patch("api.routes.run_scan", return_value=_MOCK_SCAN_RESULT)
    def test_admin_can_scan(self, mock_scan, admin_client):
        r = admin_client.post("/api/scan",
                               data=json.dumps({"target": "192.168.1.1", "kind": "ip"}),
                               content_type="application/json")
        assert r.status_code == 200
        mock_scan.assert_called_once_with("192.168.1.1", "ip")

    @patch("api.routes.run_scan", return_value=_MOCK_SCAN_RESULT)
    def test_kind_auto_detected_domain(self, mock_scan, analyst_client):
        analyst_client.post("/api/scan",
                             data=json.dumps({"target": "canada.ca"}),
                             content_type="application/json")
        mock_scan.assert_called_once_with("canada.ca", "domain")

    @patch("api.routes.run_scan", return_value=_MOCK_SCAN_RESULT)
    def test_kind_auto_detected_ip(self, mock_scan, analyst_client):
        analyst_client.post("/api/scan",
                             data=json.dumps({"target": "10.0.0.1"}),
                             content_type="application/json")
        mock_scan.assert_called_once_with("10.0.0.1", "ip")

    @patch("api.routes.run_scan", return_value=_MOCK_SCAN_RESULT)
    def test_kind_auto_detected_url(self, mock_scan, analyst_client):
        analyst_client.post("/api/scan",
                             data=json.dumps({"target": "https://example.com/path"}),
                             content_type="application/json")
        mock_scan.assert_called_once_with("https://example.com/path", "url")


# ── /api/report ───────────────────────────────────────────────────────────────

def _seed_scan(db):
    """Crée Target + Scan + Result en base, retourne scan_id."""
    target = Target(value="test.ca", kind="domain")
    db.session.add(target)
    db.session.flush()
    scan = Scan(target_id=target.id, status="done", hash_summary="abcdef")
    db.session.add(scan)
    db.session.flush()
    result = Result(
        scan_id=scan.id, source="dns", category="dns",
        data={"records": {"A": ["1.1.1.1"]}, "record_count": 1},
    )
    db.session.add(result)
    db.session.commit()
    return scan.id


class TestReportEndpoint:
    def test_report_requires_auth(self, client):
        r = client.get("/api/report/1")
        assert r.status_code == 401

    def test_report_not_found(self, analyst_client):
        r = analyst_client.get("/api/report/9999")
        assert r.status_code == 404

    def test_report_returns_scan(self, analyst_client, db, app):
        with app.app_context():
            sid = _seed_scan(db)
        r = analyst_client.get(f"/api/report/{sid}")
        assert r.status_code == 200
        data = r.get_json()
        assert data["scan_id"] == sid
        assert data["target"] == "test.ca"
        assert "sections" in data

    def test_report_json_endpoint(self, analyst_client, db, app):
        with app.app_context():
            sid = _seed_scan(db)
        r = analyst_client.get(f"/api/report/{sid}.json")
        assert r.status_code == 200
        assert r.content_type == "application/json"


# ── /api/targets ──────────────────────────────────────────────────────────────

class TestTargetsEndpoint:
    def test_targets_requires_auth(self, client):
        r = client.get("/api/targets")
        assert r.status_code == 401

    def test_targets_empty(self, analyst_client):
        r = analyst_client.get("/api/targets")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_targets_lists_entries(self, analyst_client, db, app):
        with app.app_context():
            _seed_scan(db)
        r = analyst_client.get("/api/targets")
        assert r.status_code == 200
        targets = r.get_json()
        assert len(targets) == 1
        assert targets[0]["value"] == "test.ca"


# ── /api/delta ────────────────────────────────────────────────────────────────

class TestDeltaEndpoint:
    def test_delta_requires_auth(self, client):
        r = client.get("/api/delta?a=1&b=2")
        assert r.status_code == 401

    def test_delta_missing_params(self, analyst_client):
        r = analyst_client.get("/api/delta")
        assert r.status_code == 400

    def test_delta_scan_not_found(self, analyst_client):
        r = analyst_client.get("/api/delta?a=9998&b=9999")
        assert r.status_code == 400

    def test_delta_same_target(self, analyst_client, db, app):
        with app.app_context():
            target = Target(value="delta.ca", kind="domain")
            db.session.add(target)
            db.session.flush()
            s1 = Scan(target_id=target.id, status="done", hash_summary="aaa")
            s2 = Scan(target_id=target.id, status="done", hash_summary="bbb")
            db.session.add_all([s1, s2])
            db.session.flush()
            r1 = Result(scan_id=s1.id, source="dns", category="dns",
                        data={"records": {"A": ["1.1.1.1"]}, "record_count": 1})
            r2 = Result(scan_id=s2.id, source="dns", category="dns",
                        data={"records": {"A": ["2.2.2.2"]}, "record_count": 1})
            db.session.add_all([r1, r2])
            db.session.commit()
            s1_id, s2_id = s1.id, s2.id

        r = analyst_client.get(f"/api/delta?a={s1_id}&b={s2_id}")
        assert r.status_code == 200
        data = r.get_json()
        assert data["target"] == "delta.ca"
        assert data["identical"] is False

    def test_delta_different_targets_rejected(self, analyst_client, db, app):
        with app.app_context():
            t1 = Target(value="site-a.ca", kind="domain")
            t2 = Target(value="site-b.ca", kind="domain")
            db.session.add_all([t1, t2])
            db.session.flush()
            s1 = Scan(target_id=t1.id, status="done")
            s2 = Scan(target_id=t2.id, status="done")
            db.session.add_all([s1, s2])
            db.session.commit()
            s1_id, s2_id = s1.id, s2.id

        r = analyst_client.get(f"/api/delta?a={s1_id}&b={s2_id}")
        assert r.status_code == 400


# ── /api/stats ────────────────────────────────────────────────────────────────

class TestStatsEndpoint:
    def test_stats_unknown_target(self, analyst_client):
        r = analyst_client.get("/api/stats/unknown.ca")
        assert r.status_code == 200
        data = r.get_json()
        assert data["scans"] == 0

    def test_stats_known_target(self, analyst_client, db, app):
        with app.app_context():
            _seed_scan(db)
        r = analyst_client.get("/api/stats/test.ca")
        assert r.status_code == 200
        data = r.get_json()
        assert data["scans"] == 1
        assert data["target"] == "test.ca"
