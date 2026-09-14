"""Orchestrateur : lance tous les collectors activés pour une cible."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config
from database import create_scan, finalize_scan, store_results, get_or_create_target
from collectors.dns_collector import DNSCollector
from collectors.http_collector import HTTPCollector
from collectors.whois_collector import WhoisCollector
from collectors.urlscan_collector import UrlscanCollector
from collectors.shodan_collector import ShodanCollector
from collectors.censys_collector import CensysCollector
from collectors.cve_collector import CVECollector

_REGISTRY: dict[str, type] = {
    "dns":     DNSCollector,
    "http":    HTTPCollector,
    "whois":   WhoisCollector,
    "urlscan": UrlscanCollector,
    "shodan":  ShodanCollector,
    "censys":  CensysCollector,
    "cve":     CVECollector,
}


def _build_collectors(target_kind: str) -> list:
    """Instancie les collectors activés ET compatibles avec le type de cible."""
    collectors = []
    for name, klass in _REGISTRY.items():
        if not Config.ENABLED_COLLECTORS.get(name, False):
            continue
        c = klass(target_kind)
        if c.supports():          # FIX : filtre les collectors incompatibles
            collectors.append(c)
    return collectors


def run_scan(target_value: str, target_kind: str) -> dict:
    target = get_or_create_target(target_value, target_kind)
    scan = create_scan(target)
    collectors = _build_collectors(target_kind)
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(c.collect, target_value): c for c in collectors}
        for fut in as_completed(futures):
            collector = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append({
                    "source":   collector.source,
                    "category": collector.category,
                    "data":     {},
                    "error":    f"{type(exc).__name__}: {exc}",
                })

    store_results(scan, results)

    digest = hashlib.sha256(
        json.dumps(
            {r["source"]: r.get("data", {}) for r in results},
            sort_keys=True, default=str,
        ).encode()
    ).hexdigest()

    finalize_scan(scan, status="done", hash_summary=digest)

    return {
        "scan_id": scan.id,
        "target":  target_value,
        "kind":    target_kind,
        "hash":    digest,
        "results": results,
    }
