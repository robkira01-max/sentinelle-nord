"""Tests P5 — CPCSC Niveau 1 auto-évaluation."""
import json

import pytest

from compliance.cpcsc_l1 import (
    CONTROLS,
    Control,
    as_dict,
    compute_score,
    _STATUS_WEIGHT,
)


# ---------------------------------------------------------------------------
# Données brutes — intégrité du catalogue
# ---------------------------------------------------------------------------

class TestControlCatalog:
    def test_exactly_17_controls(self):
        assert len(CONTROLS) == 17

    def test_all_ids_unique(self):
        ids = [c.id for c in CONTROLS]
        assert len(ids) == len(set(ids))

    def test_all_ids_follow_cpcsc_format(self):
        import re
        pattern = re.compile(r"^[A-Z]+\.L1-\d+\.\d+\.\d+$")
        for c in CONTROLS:
            assert pattern.match(c.id), f"Format invalide : {c.id}"

    def test_valid_statuses(self):
        valid = {"IMPLEMENTED", "PARTIAL", "PROCEDURAL", "NOT_IMPLEMENTED"}
        for c in CONTROLS:
            assert c.status in valid, f"{c.id} statut inconnu : {c.status}"

    def test_valid_priorities(self):
        valid = {"HIGH", "MEDIUM", "LOW"}
        for c in CONTROLS:
            assert c.priority in valid, f"{c.id} priorité inconnue : {c.priority}"

    def test_all_controls_have_description(self):
        for c in CONTROLS:
            assert c.description.strip(), f"{c.id} description vide"

    def test_all_controls_have_evidence(self):
        for c in CONTROLS:
            assert c.evidence.strip(), f"{c.id} evidence vide"

    def test_partial_controls_have_gap(self):
        for c in CONTROLS:
            if c.status == "PARTIAL":
                assert c.gap.strip(), f"{c.id} PARTIAL sans gap documenté"

    def test_domains_covered(self):
        domains = {c.domain for c in CONTROLS}
        required = {
            "Contrôle d'accès",
            "Identification et authentification",
            "Protection des médias",
            "Protection physique",
            "Protection des systèmes et des communications",
            "Intégrité du système et de l'information",
        }
        assert required.issubset(domains)

    def test_ac_controls_count(self):
        ac = [c for c in CONTROLS if c.id.startswith("AC")]
        assert len(ac) == 4

    def test_ia_controls_count(self):
        ia = [c for c in CONTROLS if c.id.startswith("IA")]
        assert len(ia) == 2

    def test_si_controls_count(self):
        si = [c for c in CONTROLS if c.id.startswith("SI")]
        assert len(si) == 4

    def test_pe_controls_count(self):
        pe = [c for c in CONTROLS if c.id.startswith("PE")]
        assert len(pe) == 4


# ---------------------------------------------------------------------------
# compute_score()
# ---------------------------------------------------------------------------

class TestComputeScore:
    def test_returns_required_keys(self):
        s = compute_score()
        for key in ("total", "score_pct", "counts", "assessment_date", "level", "framework"):
            assert key in s

    def test_total_matches_controls(self):
        s = compute_score()
        assert s["total"] == 17

    def test_score_pct_in_range(self):
        s = compute_score()
        assert 0.0 <= s["score_pct"] <= 100.0

    def test_score_all_implemented(self):
        controls = [
            Control(
                id=f"XX.L1-1.1.{i}", domain="Test", title="t",
                description="d", status="IMPLEMENTED", evidence="e",
            )
            for i in range(5)
        ]
        s = compute_score(controls)
        assert s["score_pct"] == 100.0

    def test_score_all_not_implemented(self):
        controls = [
            Control(
                id=f"XX.L1-1.1.{i}", domain="Test", title="t",
                description="d", status="NOT_IMPLEMENTED", evidence="e",
            )
            for i in range(4)
        ]
        s = compute_score(controls)
        assert s["score_pct"] == 0.0

    def test_score_mixed(self):
        controls = [
            Control(id="XX.L1-1.1.1", domain="D", title="t",
                    description="d", status="IMPLEMENTED", evidence="e"),
            Control(id="XX.L1-1.1.2", domain="D", title="t",
                    description="d", status="NOT_IMPLEMENTED", evidence="e"),
        ]
        s = compute_score(controls)
        assert s["score_pct"] == 50.0

    def test_counts_sum_to_total(self):
        s = compute_score()
        assert sum(s["counts"].values()) == s["total"]

    def test_assessment_date_format(self):
        import re
        s = compute_score()
        assert re.match(r"\d{4}-\d{2}-\d{2}", s["assessment_date"])


# ---------------------------------------------------------------------------
# as_dict()
# ---------------------------------------------------------------------------

class TestAsDict:
    def test_structure(self):
        d = as_dict()
        assert "summary" in d
        assert "domains" in d

    def test_domains_not_empty(self):
        d = as_dict()
        assert len(d["domains"]) >= 1

    def test_each_control_has_status_label(self):
        d = as_dict()
        for items in d["domains"].values():
            for item in items:
                assert "status_label" in item
                assert item["status_label"]

    def test_json_serializable(self):
        d = as_dict()
        raw = json.dumps(d)
        parsed = json.loads(raw)
        assert parsed["summary"]["total"] == 17


# ---------------------------------------------------------------------------
# Routes HTTP  (utilise les fixtures client/analyst_client de conftest.py)
# ---------------------------------------------------------------------------

class TestComplianceRoutes:
    def test_dashboard_requires_auth(self, client):
        r = client.get("/compliance/cpcsc", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_json_requires_auth(self, client):
        r = client.get("/compliance/cpcsc.json", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_export_requires_auth(self, client):
        r = client.get("/compliance/cpcsc/export", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_dashboard_ok_analyst(self, analyst_client):
        r = analyst_client.get("/compliance/cpcsc")
        assert r.status_code == 200
        assert b"CPCSC" in r.data

    def test_dashboard_contains_score(self, analyst_client):
        r = analyst_client.get("/compliance/cpcsc")
        assert b"%" in r.data

    def test_json_ok_analyst(self, analyst_client):
        r = analyst_client.get("/compliance/cpcsc.json")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["summary"]["total"] == 17

    def test_json_contains_domains(self, analyst_client):
        r = analyst_client.get("/compliance/cpcsc.json")
        data = json.loads(r.data)
        assert len(data["domains"]) >= 6
