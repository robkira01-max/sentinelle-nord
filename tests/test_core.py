"""Tests — logique métier (aggregator, normalizer, delta, collectors)."""
from unittest.mock import patch, MagicMock

import pytest


# ── _guess_kind helper ────────────────────────────────────────────────────────

class TestGuessKind:
    def test_detects_url_https(self):
        from api.routes import _guess_kind
        assert _guess_kind("https://example.com") == "url"

    def test_detects_url_http(self):
        from api.routes import _guess_kind
        assert _guess_kind("http://example.com/path") == "url"

    def test_detects_ipv4(self):
        from api.routes import _guess_kind
        assert _guess_kind("192.168.1.1") == "ip"
        assert _guess_kind("10.0.0.1") == "ip"

    def test_detects_domain(self):
        from api.routes import _guess_kind
        assert _guess_kind("canada.ca") == "domain"
        assert _guess_kind("sub.example.com") == "domain"
        assert _guess_kind("example") == "domain"


# ── Normalizer ────────────────────────────────────────────────────────────────

class TestNormalizer:
    def test_make_result_structure(self):
        from core.normalizer import make_result
        r = make_result("dns", "dns", {"records": {}})
        assert r["source"] == "dns"
        assert r["category"] == "dns"
        assert r["data"] == {"records": {}}
        assert r["error"] is None

    def test_make_result_with_error(self):
        from core.normalizer import make_result
        r = make_result("http", "http", {}, error="timeout")
        assert r["error"] == "timeout"
        assert r["data"] == {}

    def test_normalize_dns(self):
        from core.normalizer import normalize_dns
        records = {"A": ["1.1.1.1", "2.2.2.2"], "MX": ["mail.example.com"]}
        result = normalize_dns(records)
        assert result["record_count"] == 3
        assert "records" in result

    def test_normalize_dns_empty(self):
        from core.normalizer import normalize_dns
        result = normalize_dns({})
        assert result["record_count"] == 0

    def test_normalize_whois(self):
        from core.normalizer import normalize_whois
        raw = {
            "domain_name": "example.com",
            "registrar": "Test Registrar",
            "emails": ["admin@example.com"],
        }
        result = normalize_whois(raw)
        assert result["domain_name"] == "example.com"
        assert result["registrar"] == "Test Registrar"
        assert "creation_date" not in result  # None fields excluded

    def test_normalize_urlscan(self):
        from core.normalizer import normalize_urlscan
        raw = {
            "page": {"url": "https://example.com", "domain": "example.com",
                     "ip": "1.2.3.4", "country": "CA"},
            "verdicts": {"overall": {"score": 0}},
        }
        result = normalize_urlscan(raw)
        assert result["domain"] == "example.com"
        assert result["ip"] == "1.2.3.4"

    def test_normalize_cve_truncates_at_50(self):
        from core.normalizer import normalize_cve
        vulns = [{"cve": {"id": f"CVE-2024-{i:04d}", "metrics": {}}}
                 for i in range(100)]
        result = normalize_cve({"vulnerabilities": vulns})
        assert result["total"] == 100
        assert len(result["items"]) <= 50


# ── BaseCollector ─────────────────────────────────────────────────────────────

class TestBaseCollector:
    def test_supports_returns_true_by_default(self):
        from collectors.base import BaseCollector

        class FakeCollector(BaseCollector):
            source = "fake"
            category = "test"
            def collect(self, target: str) -> dict:
                return self._result(self.source, self.category, {})

        c = FakeCollector("domain")
        assert c.supports() is True

    def test_result_helper(self):
        from collectors.base import BaseCollector

        class FakeCollector(BaseCollector):
            source = "fake"
            category = "test"
            def collect(self, target: str) -> dict:
                return self._result(self.source, self.category, {"key": "val"})

        c = FakeCollector("ip")
        r = c.collect("1.2.3.4")
        assert r == {"source": "fake", "category": "test",
                     "data": {"key": "val"}, "error": None}


# ── DNS Collector supports() ──────────────────────────────────────────────────

class TestDNSCollectorSupports:
    def test_supports_domain(self):
        from collectors.dns_collector import DNSCollector
        assert DNSCollector("domain").supports() is True

    def test_does_not_support_ip(self):
        from collectors.dns_collector import DNSCollector
        assert DNSCollector("ip").supports() is False

    def test_does_not_support_url(self):
        from collectors.dns_collector import DNSCollector
        assert DNSCollector("url").supports() is False


# ── HTTP Collector supports() ─────────────────────────────────────────────────

class TestHTTPCollectorSupports:
    def test_supports_domain(self):
        from collectors.http_collector import HTTPCollector
        assert HTTPCollector("domain").supports() is True

    def test_supports_url(self):
        from collectors.http_collector import HTTPCollector
        assert HTTPCollector("url").supports() is True

    def test_does_not_support_ip(self):
        from collectors.http_collector import HTTPCollector
        assert HTTPCollector("ip").supports() is False


# ── Aggregator — _build_collectors ───────────────────────────────────────────

class TestBuildCollectors:
    def test_returns_only_enabled_collectors(self, monkeypatch):
        from config import Config
        monkeypatch.setattr(Config, "ENABLED_COLLECTORS", {
            "dns": True, "http": False, "whois": False,
            "urlscan": False, "shodan": False, "censys": False, "cve": False,
        })
        from core.aggregator import _build_collectors
        collectors = _build_collectors("domain")
        names = [c.source for c in collectors]
        assert "dns" in names
        assert "http" not in names

    def test_filters_incompatible_target_kind(self, monkeypatch):
        from config import Config
        monkeypatch.setattr(Config, "ENABLED_COLLECTORS", {
            "dns": True, "http": True, "whois": False,
            "urlscan": False, "shodan": False, "censys": False, "cve": False,
        })
        from core.aggregator import _build_collectors
        collectors = _build_collectors("ip")  # dns doesn't support ip
        names = [c.source for c in collectors]
        assert "dns" not in names
        assert "http" not in names  # http also doesn't support ip


# ── Aggregator — run_scan (mocked DB) ─────────────────────────────────────────

class TestRunScan:
    @patch("core.aggregator.finalize_scan")
    @patch("core.aggregator.store_results")
    @patch("core.aggregator.create_scan")
    @patch("core.aggregator.get_or_create_target")
    @patch("core.aggregator._build_collectors")
    def test_run_scan_returns_expected_shape(
        self, mock_build, mock_target, mock_create_scan,
        mock_store, mock_finalize
    ):
        mock_target.return_value = MagicMock(id=1)
        mock_scan = MagicMock(id=42)
        mock_create_scan.return_value = mock_scan

        fake_collector = MagicMock()
        fake_collector.source = "dns"
        fake_collector.category = "dns"
        fake_collector.collect.return_value = {
            "source": "dns", "category": "dns",
            "data": {"records": {"A": ["1.1.1.1"]}, "record_count": 1},
            "error": None,
        }
        mock_build.return_value = [fake_collector]

        from core.aggregator import run_scan
        result = run_scan("test.ca", "domain")

        assert result["scan_id"] == 42
        assert result["target"] == "test.ca"
        assert result["kind"] == "domain"
        assert "hash" in result
        assert len(result["results"]) == 1
        mock_finalize.assert_called_once()
        mock_store.assert_called_once()

    @patch("core.aggregator.finalize_scan")
    @patch("core.aggregator.store_results")
    @patch("core.aggregator.create_scan")
    @patch("core.aggregator.get_or_create_target")
    @patch("core.aggregator._build_collectors")
    def test_run_scan_catches_collector_exceptions(
        self, mock_build, mock_target, mock_create_scan,
        mock_store, mock_finalize
    ):
        mock_target.return_value = MagicMock(id=1)
        mock_create_scan.return_value = MagicMock(id=1)

        failing_collector = MagicMock()
        failing_collector.source = "shodan"
        failing_collector.category = "infra"
        failing_collector.collect.side_effect = RuntimeError("API down")
        mock_build.return_value = [failing_collector]

        from core.aggregator import run_scan
        result = run_scan("test.ca", "domain")

        assert len(result["results"]) == 1
        assert result["results"][0]["error"] is not None
        assert "RuntimeError" in result["results"][0]["error"]


# ── Delta logic (unit) ────────────────────────────────────────────────────────

class TestDeltaLogic:
    def test_compute_delta_identical_scans(self, app, db):
        with app.app_context():
            from models import Target, Scan, Result
            from monitoring.delta import compute_delta

            t = Target(value="delta-unit.ca", kind="domain")
            db.session.add(t)
            db.session.flush()

            data = {"records": {"A": ["1.1.1.1"]}, "record_count": 1}
            s1 = Scan(target_id=t.id, status="done", hash_summary="same")
            s2 = Scan(target_id=t.id, status="done", hash_summary="same")
            db.session.add_all([s1, s2])
            db.session.flush()
            db.session.add(Result(scan_id=s1.id, source="dns",
                                  category="dns", data=data))
            db.session.add(Result(scan_id=s2.id, source="dns",
                                  category="dns", data=data))
            db.session.commit()

            delta = compute_delta(s1.id, s2.id)
            assert delta["identical"] is True
            assert delta["stats"]["changed"] == 0

    def test_compute_delta_changed_data(self, app, db):
        with app.app_context():
            from models import Target, Scan, Result
            from monitoring.delta import compute_delta

            t = Target(value="changed.ca", kind="domain")
            db.session.add(t)
            db.session.flush()

            s1 = Scan(target_id=t.id, status="done", hash_summary="aaa")
            s2 = Scan(target_id=t.id, status="done", hash_summary="bbb")
            db.session.add_all([s1, s2])
            db.session.flush()
            db.session.add(Result(scan_id=s1.id, source="dns",
                                  category="dns",
                                  data={"records": {"A": ["1.1.1.1"]}}))
            db.session.add(Result(scan_id=s2.id, source="dns",
                                  category="dns",
                                  data={"records": {"A": ["2.2.2.2"]}}))
            db.session.commit()

            delta = compute_delta(s1.id, s2.id)
            assert delta["identical"] is False
            assert delta["stats"]["changed"] == 1

    def test_target_stats_no_scans(self, app, db):
        with app.app_context():
            from monitoring.delta import target_stats
            result = target_stats("nonexistent.ca")
            assert result["scans"] == 0


# ── CrtshCollector ────────────────────────────────────────────────────────────

class TestCrtshCollectorSupports:
    def test_supports_domain(self):
        from collectors.crtsh_collector import CrtshCollector
        assert CrtshCollector("domain").supports() is True

    def test_rejects_ip(self):
        from collectors.crtsh_collector import CrtshCollector
        assert CrtshCollector("ip").supports() is False

    def test_rejects_url(self):
        from collectors.crtsh_collector import CrtshCollector
        assert CrtshCollector("url").supports() is False


class TestCrtshCollect:
    def test_collect_returns_subdomains(self):
        fake_json = [
            {
                "name_value": "www.example.com\nmail.example.com",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "not_before":  "2026-01-01T00:00:00",
                "not_after":   "2026-04-01T00:00:00",
                "serial_number": "abc123",
            }
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_json
        mock_resp.raise_for_status.return_value = None

        with patch("collectors.crtsh_collector.requests.get", return_value=mock_resp):
            from collectors.crtsh_collector import CrtshCollector
            result = CrtshCollector("domain").collect("example.com")

        assert result["source"] == "crtsh"
        assert result["category"] == "subdomains"
        assert result["error"] is None
        assert result["data"]["total"] == 2
        subs = [s["subdomain"] for s in result["data"]["subdomains"]]
        assert "www.example.com" in subs
        assert "mail.example.com" in subs

    def test_collect_returns_error_on_timeout(self):
        import requests as req
        with patch("collectors.crtsh_collector.requests.get",
                   side_effect=req.exceptions.Timeout):
            from collectors.crtsh_collector import CrtshCollector
            result = CrtshCollector("domain").collect("example.com")

        assert result["error"] is not None
        assert result["data"] == {}

    def test_collect_deduplicates_subdomains(self):
        fake_json = [
            {
                "name_value": "www.example.com",
                "issuer_name": "O=Let's Encrypt",
                "not_before":  "2026-01-01T00:00:00",
                "not_after":   "2026-04-01T00:00:00",
                "serial_number": "a1",
            },
            {
                "name_value": "www.example.com",
                "issuer_name": "O=Let's Encrypt",
                "not_before":  "2026-02-01T00:00:00",
                "not_after":   "2026-05-01T00:00:00",
                "serial_number": "a2",
            },
        ]
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = fake_json

        with patch("collectors.crtsh_collector.requests.get", return_value=mock_resp):
            from collectors.crtsh_collector import CrtshCollector
            result = CrtshCollector("domain").collect("example.com")

        assert result["data"]["total"] == 1


# ── WordpressCollector ────────────────────────────────────────────────────────

class TestWordpressCollectorSupports:
    def test_supports_domain(self):
        from collectors.wordpress_collector import WordpressCollector
        assert WordpressCollector("domain").supports() is True

    def test_supports_url(self):
        from collectors.wordpress_collector import WordpressCollector
        assert WordpressCollector("url").supports() is True

    def test_rejects_ip(self):
        from collectors.wordpress_collector import WordpressCollector
        assert WordpressCollector("ip").supports() is False


class TestWordpressCollect:
    def test_not_wordpress_site(self):
        def _fake_get(url, **kw):
            r = MagicMock()
            # wp-login.php must return non-WP status to avoid false positive
            r.status_code = 404 if "wp-login" in url else 200
            r.text = "<html><body>Hello world</body></html>"
            return r

        with patch("collectors.wordpress_collector.requests.get",
                   side_effect=_fake_get):
            from collectors.wordpress_collector import WordpressCollector
            result = WordpressCollector("domain").collect("example.com")

        assert result["source"] == "wordpress"
        assert result["category"] == "cms"
        assert result["data"]["is_wordpress"] is False
        assert result["data"]["users"] == []

    def test_detects_wordpress_by_keyword(self):
        def _fake_get(url, **kw):
            r = MagicMock()
            r.status_code = 200
            if "/wp-json/wp/v2/users" in url:
                r.json.return_value = [{"id": 1, "slug": "admin", "name": "Admin"}]
            elif "/wp-json/" == url[-9:]:
                r.json.return_value = {"namespaces": ["wp/v2"]}
            elif "xmlrpc.php" in url:
                r.status_code = 404
            elif "readme.html" in url or "license.txt" in url:
                r.text = "wordpress 6.4.3"
            else:
                r.text = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
            return r
        mock_head = MagicMock()
        mock_head.status_code = 404

        with patch("collectors.wordpress_collector.requests.get", side_effect=_fake_get), \
             patch("collectors.wordpress_collector.requests.head", return_value=mock_head):
            from collectors.wordpress_collector import WordpressCollector
            result = WordpressCollector("domain").collect("example.com")

        assert result["data"]["is_wordpress"] is True


# ── BackupCollector ───────────────────────────────────────────────────────────

class TestBackupCollectorSupports:
    def test_supports_domain(self):
        from collectors.backup_collector import BackupCollector
        assert BackupCollector("domain").supports() is True

    def test_supports_url(self):
        from collectors.backup_collector import BackupCollector
        assert BackupCollector("url").supports() is True

    def test_rejects_ip(self):
        from collectors.backup_collector import BackupCollector
        assert BackupCollector("ip").supports() is False


class TestBackupCollect:
    def test_clean_site_empty_result(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("collectors.backup_collector.requests.head",
                   return_value=mock_resp), \
             patch("collectors.backup_collector.requests.get",
                   return_value=mock_resp):
            from collectors.backup_collector import BackupCollector
            result = BackupCollector("domain").collect("example.com")

        assert result["source"] == "backup"
        assert result["category"] == "exposure"
        assert result["data"]["exposed_files"] == []
        assert result["data"]["git_exposed"] is False
        assert result["data"]["summary"]["total_exposed"] == 0

    def test_detects_exposed_env_file(self):
        def _fake_head(url, **kw):
            r = MagicMock()
            r.status_code = 200 if url.endswith("/.env") else 404
            r.headers = {"content-length": "512", "content-type": "text/plain"}
            return r

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 404

        with patch("collectors.backup_collector.requests.head",
                   side_effect=_fake_head), \
             patch("collectors.backup_collector.requests.get",
                   return_value=mock_get_resp):
            from collectors.backup_collector import BackupCollector
            result = BackupCollector("domain").collect("example.com")

        exposed_paths = [f["path"] for f in result["data"]["exposed_files"]]
        assert "/.env" in exposed_paths
        env_entry = next(f for f in result["data"]["exposed_files"]
                         if f["path"] == "/.env")
        assert env_entry["risk"] == "CRITIQUE"

    def test_git_validation_rejects_spa_html(self):
        """/.git/HEAD returning HTML (SPA 200) must not be flagged as exposed."""
        def _fake_get(url, **kw):
            r = MagicMock()
            if ".git" in url:
                r.status_code = 200
                r.text = "<!DOCTYPE html><html><body>Not Found</body></html>"
                r.content = b"<!DOCTYPE html>"
                r.headers = {"content-type": "text/html"}
            else:
                r.status_code = 200
                r.text = ""
                r.headers = {}
            return r

        mock_head = MagicMock()
        mock_head.status_code = 404

        with patch("collectors.backup_collector.requests.head",
                   return_value=mock_head), \
             patch("collectors.backup_collector.requests.get",
                   side_effect=_fake_get):
            from collectors.backup_collector import BackupCollector
            result = BackupCollector("domain").collect("example.com")

        assert result["data"]["git_exposed"] is False

    def test_git_head_valid_content_flagged(self):
        """/.git/HEAD returning 'ref: refs/heads/main' must be flagged CRITIQUE."""
        def _fake_get(url, **kw):
            r = MagicMock()
            if ".git/HEAD" in url:
                r.status_code = 200
                r.text = "ref: refs/heads/main"
                r.content = b"ref: refs/heads/main"
                r.headers = {"content-type": "text/plain"}
            elif ".git/config" in url:
                r.status_code = 200
                r.text = "[core]\n\trepositoryformatversion = 0"
                r.content = b"[core]"
                r.headers = {"content-type": "text/plain"}
            else:
                r.status_code = 200
                r.text = ""
                r.headers = {}
            return r

        mock_head = MagicMock()
        mock_head.status_code = 404

        with patch("collectors.backup_collector.requests.head",
                   return_value=mock_head), \
             patch("collectors.backup_collector.requests.get",
                   side_effect=_fake_get):
            from collectors.backup_collector import BackupCollector
            result = BackupCollector("domain").collect("example.com")

        assert result["data"]["git_exposed"] is True
        git_entries = [f for f in result["data"]["exposed_files"]
                       if f["risk"] == "CRITIQUE" and ".git" in f["path"]]
        assert len(git_entries) >= 1
