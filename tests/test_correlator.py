"""Tests P6 — corrélation d'actifs par organisation."""
import json

import pytest

from core.correlator import (
    AssetFeatures,
    OrgCluster,
    _find,
    _make_uf,
    _norm_asn,
    _norm_domain,
    _norm_ns,
    _norm_org,
    _union,
    clusters_to_dict,
    correlate,
    extract_features,
)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_norm_asn_extracts_number(self):
        assert _norm_asn("AS15169 Google LLC") == "AS15169"

    def test_norm_asn_already_clean(self):
        assert _norm_asn("AS12345") == "AS12345"

    def test_norm_asn_lowercase_input(self):
        assert _norm_asn("as9999") == "AS9999"

    def test_norm_asn_none(self):
        assert _norm_asn(None) is None

    def test_norm_asn_empty(self):
        assert _norm_asn("") is None

    def test_norm_org_strips_and_lowercases(self):
        assert _norm_org("  Acme Corp  ") == "acme corp"

    def test_norm_org_none(self):
        assert _norm_org(None) is None

    def test_norm_ns_normalizes(self):
        assert _norm_ns(["NS1.EXAMPLE.COM.", "ns2.example.com"]) == [
            "ns1.example.com",
            "ns2.example.com",
        ]

    def test_norm_ns_string_input(self):
        result = _norm_ns("ns1.example.com.")
        assert result == ["ns1.example.com"]

    def test_norm_ns_empty(self):
        assert _norm_ns([]) == []
        assert _norm_ns(None) == []

    def test_norm_domain_strips_wildcard(self):
        assert _norm_domain("*.example.com") == "example.com"

    def test_norm_domain_lowercase(self):
        assert _norm_domain("EXAMPLE.COM") == "example.com"

    def test_norm_domain_none(self):
        assert _norm_domain(None) == ""


# ---------------------------------------------------------------------------
# extract_features()
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def _results(self, urlscan=None, whois=None, http=None, shodan=None):
        out = []
        if urlscan:
            out.append({"source": "urlscan", "data": urlscan})
        if whois:
            out.append({"source": "whois",   "data": whois})
        if http:
            out.append({"source": "http",    "data": http})
        if shodan:
            out.append({"source": "shodan",  "data": shodan})
        return out

    def test_extracts_asn_from_urlscan(self):
        f = extract_features("ex.com", self._results(
            urlscan={"asn": "AS15169 Google LLC", "ip": "8.8.8.8"}
        ))
        assert f.asn == "AS15169"
        assert f.ip == "8.8.8.8"

    def test_extracts_org_from_whois(self):
        f = extract_features("ex.com", self._results(
            whois={"org": "Acme Inc", "name_servers": ["ns1.acme.com."]}
        ))
        assert f.whois_org == "acme inc"
        assert "ns1.acme.com" in f.nameservers

    def test_extracts_ssl_sans_from_http(self):
        f = extract_features("ex.com", self._results(
            http={"ssl": {"sans": ["example.com", "www.example.com", "*.example.com"]}}
        ))
        assert "example.com" in f.ssl_sans
        assert "www.example.com" in f.ssl_sans
        # wildcard stripped
        assert "example.com" in f.ssl_sans

    def test_shodan_asn_fallback(self):
        f = extract_features("ex.com", self._results(
            shodan={"org": "AS9876 SomeISP", "ip": "1.2.3.4"}
        ))
        assert f.asn == "AS9876"

    def test_urlscan_takes_priority_over_shodan_for_asn(self):
        f = extract_features("ex.com", self._results(
            urlscan={"asn": "AS111 First", "ip": "1.1.1.1"},
            shodan={"org": "AS222 Second", "ip": "2.2.2.2"},
        ))
        assert f.asn == "AS111"

    def test_empty_results(self):
        f = extract_features("ex.com", [])
        assert f.asn is None
        assert f.whois_org is None
        assert f.nameservers == []


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class TestUnionFind:
    def test_find_self(self):
        parent, _ = _make_uf(["a", "b", "c"])
        assert _find(parent, "a") == "a"

    def test_union_connects(self):
        parent, rank = _make_uf(["a", "b", "c"])
        _union(parent, rank, "a", "b")
        assert _find(parent, "a") == _find(parent, "b")

    def test_union_idempotent(self):
        parent, rank = _make_uf(["a", "b"])
        _union(parent, rank, "a", "b")
        _union(parent, rank, "a", "b")
        assert _find(parent, "a") == _find(parent, "b")

    def test_transitive(self):
        parent, rank = _make_uf(["a", "b", "c"])
        _union(parent, rank, "a", "b")
        _union(parent, rank, "b", "c")
        assert _find(parent, "a") == _find(parent, "c")


# ---------------------------------------------------------------------------
# correlate()
# ---------------------------------------------------------------------------

class TestCorrelate:
    def _feat(self, target, **kw) -> AssetFeatures:
        return AssetFeatures(target=target, **kw)

    def test_empty_input(self):
        assert correlate([]) == []

    def test_single_target(self):
        clusters = correlate([self._feat("solo.com", asn="AS1")])
        assert len(clusters) == 1
        assert clusters[0].targets == ["solo.com"]

    def test_two_same_asn(self):
        feats = [
            self._feat("a.com", asn="AS999"),
            self._feat("b.com", asn="AS999"),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1
        assert set(multi[0].targets) == {"a.com", "b.com"}

    def test_signal_recorded(self):
        feats = [
            self._feat("a.com", asn="AS999"),
            self._feat("b.com", asn="AS999"),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1][0]
        types = [s.signal_type for s in multi.signals]
        assert "ASN" in types

    def test_different_asns_no_merge(self):
        feats = [
            self._feat("a.com", asn="AS1"),
            self._feat("b.com", asn="AS2"),
        ]
        clusters = correlate(feats)
        assert all(len(c.targets) == 1 for c in clusters)

    def test_whois_org_merges(self):
        feats = [
            self._feat("x.com", whois_org="acme corp"),
            self._feat("y.com", whois_org="acme corp"),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1

    def test_nameserver_merges(self):
        feats = [
            self._feat("a.com", nameservers=["ns1.shared.net"]),
            self._feat("b.com", nameservers=["ns1.shared.net"]),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1

    def test_ip_merges(self):
        feats = [
            self._feat("a.com", ip="10.0.0.1"),
            self._feat("b.com", ip="10.0.0.1"),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1

    def test_ssl_san_merges(self):
        feats = [
            self._feat("a.com", ssl_sans=["a.com", "b.com"]),
            self._feat("b.com", ssl_sans=["a.com", "b.com"]),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1

    def test_three_targets_two_signals(self):
        feats = [
            self._feat("a.com", asn="AS42", whois_org="bigcorp"),
            self._feat("b.com", asn="AS42"),
            self._feat("c.com", whois_org="bigcorp"),
        ]
        clusters = correlate(feats)
        # All three should be in one cluster via transitive union
        multi = [c for c in clusters if len(c.targets) > 1]
        assert len(multi) == 1
        assert len(multi[0].targets) == 3

    def test_results_sorted_by_size_desc(self):
        feats = [
            self._feat("solo.com"),
            self._feat("a.com", asn="AS1"),
            self._feat("b.com", asn="AS1"),
            self._feat("c.com", asn="AS1"),
        ]
        clusters = correlate(feats)
        sizes = [len(c.targets) for c in clusters]
        assert sizes == sorted(sizes, reverse=True)

    def test_inferred_org_prefers_asn(self):
        feats = [
            self._feat("a.com", asn="AS999", whois_org="some org"),
            self._feat("b.com", asn="AS999"),
        ]
        clusters = correlate(feats)
        multi = [c for c in clusters if len(c.targets) > 1][0]
        assert multi.inferred_org == "AS999"


# ---------------------------------------------------------------------------
# clusters_to_dict()
# ---------------------------------------------------------------------------

class TestClustersToDict:
    def test_structure(self):
        feats = [
            AssetFeatures("a.com", asn="AS1"),
            AssetFeatures("b.com", asn="AS1"),
        ]
        d = clusters_to_dict(correlate(feats))
        assert "total_clusters" in d
        assert "total_targets" in d
        assert "linked_targets" in d
        assert "clusters" in d

    def test_json_serializable(self):
        feats = [AssetFeatures("x.com", asn="AS2")]
        d = clusters_to_dict(correlate(feats))
        raw = json.dumps(d)
        assert json.loads(raw)["total_targets"] == 1

    def test_linked_targets_count(self):
        feats = [
            AssetFeatures("a.com", asn="AS5"),
            AssetFeatures("b.com", asn="AS5"),
            AssetFeatures("solo.com"),
        ]
        d = clusters_to_dict(correlate(feats))
        assert d["linked_targets"] == 2
        assert d["total_targets"] == 3


# ---------------------------------------------------------------------------
# Routes HTTP
# ---------------------------------------------------------------------------

class TestCorrelateRoutes:
    def test_api_correlate_requires_auth(self, client):
        r = client.get("/api/correlate", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_correlate_view_requires_auth(self, client):
        r = client.get("/correlate", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_api_correlate_analyst_ok(self, analyst_client):
        r = analyst_client.get("/api/correlate")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "clusters" in data
        assert "total_targets" in data

    def test_correlate_view_analyst_ok(self, analyst_client):
        r = analyst_client.get("/correlate")
        assert r.status_code == 200
        assert b"Corr" in r.data

    def test_api_correlate_returns_valid_schema(self, analyst_client):
        r = analyst_client.get("/api/correlate")
        data = json.loads(r.data)
        for c in data["clusters"]:
            assert "id" in c
            assert "targets" in c
            assert "signals" in c
            assert "inferred_org" in c
