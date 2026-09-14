"""Normalisation des résultats hétérogènes vers un schéma commun.

Schéma uniforme :
  {"source": str, "category": str, "data": dict, "error": str|None}
"""
from typing import Any


def make_result(source: str, category: str,
                data: Any, error: str | None = None) -> dict:
    return {"source": source, "category": category,
            "data": data or {}, "error": error}


def normalize_dns(records: dict[str, list[str]]) -> dict:
    return {
        "records": records,
        "record_count": sum(len(v) for v in records.values()),
    }


def _str(v):
    """Sérialise datetime/liste pour JSON."""
    if isinstance(v, list):
        return [_str(i) for i in v]
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def normalize_whois(raw: dict) -> dict:
    keep = ["domain_name", "registrar", "creation_date", "expiration_date",
            "updated_date", "name_servers", "status", "emails", "org", "country"]
    return {k: _str(raw.get(k)) for k in keep if raw.get(k) is not None}


def normalize_http(data: dict) -> dict:
    return data


def normalize_shodan(raw: dict) -> dict:
    return {
        "ip":        raw.get("ip_str"),
        "org":       raw.get("org"),
        "isp":       raw.get("isp"),
        "os":        raw.get("os"),
        "ports":     raw.get("ports", []),
        "hostnames": raw.get("hostnames", []),
        "vulns":     list((raw.get("vulns") or {}).keys()),
        "country":   raw.get("country_code"),
    }


def normalize_censys(raw: dict) -> dict:
    return {
        "ip": raw.get("ip"),
        "services": [
            {"port":    s.get("port"),
             "service": s.get("service_name"),
             "banner":  (s.get("banner") or "")[:512]}
            for s in raw.get("services", [])
        ],
    }


def normalize_urlscan(raw: dict) -> dict:
    page = raw.get("page", {}) or {}
    return {
        "url":      page.get("url"),
        "domain":   page.get("domain"),
        "ip":       page.get("ip"),
        "asn":      page.get("asn"),
        "country":  page.get("country"),
        "server":   page.get("server"),
        "verdicts": raw.get("verdicts", {}),
        "stats":    raw.get("stats", {}),
    }


def normalize_cve(raw: dict) -> dict:
    vulns = raw.get("vulnerabilities", []) or []
    items = []
    for v in vulns[:50]:
        cve_obj = v.get("cve", {})
        metrics = cve_obj.get("metrics", {})
        cvss31 = metrics.get("cvssMetricV31", [{}])
        cvss_data = cvss31[0].get("cvssData", {}) if cvss31 else {}
        items.append({
            "cve":      cve_obj.get("id"),
            "score":    cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
        })
    return {"total": len(vulns), "items": items}
