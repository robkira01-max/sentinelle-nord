"""Collecteur crt.sh — Certificate Transparency logs → sous-domaines."""
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from config import Config
from collectors.base import BaseCollector
from core.normalizer import make_result

import requests


class CrtshCollector(BaseCollector):
    source   = "crtsh"
    category = "subdomains"

    def supports(self) -> bool:
        return self.target_kind == "domain"

    def collect(self, target: str) -> dict:
        subdomains = self._query_crtsh(target)
        if subdomains and "error" in subdomains[0]:
            return make_result(self.source, self.category, {},
                               error=subdomains[0]["error"])

        # Regrouper par sous-domaine unique, garder cert le plus récent
        by_sub: dict[str, dict] = {}
        for entry in subdomains:
            sub = entry["subdomain"]
            if sub not in by_sub or entry["not_after"] > by_sub[sub]["not_after"]:
                by_sub[sub] = entry

        issuers: dict[str, int] = defaultdict(int)
        for e in by_sub.values():
            issuers[e["issuer"]] += 1

        data = {
            "total":      len(by_sub),
            "subdomains": sorted(by_sub.values(), key=lambda x: x["subdomain"]),
            "issuers":    dict(sorted(issuers.items(), key=lambda x: -x[1])[:10]),
            "wildcard":   sum(1 for s in by_sub if s.startswith("*.")),
        }
        return make_result(self.source, self.category, data)

    # ── privé ──────────────────────────────────────────────────────

    def _query_crtsh(self, domain: str) -> list[dict]:
        urls = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://crt.sh/?q={domain}&output=json",
        ]
        for url in urls:
            try:
                resp = requests.get(url, timeout=20,
                                    headers={"Accept": "application/json"})
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.exceptions.Timeout:
                continue
            except Exception as exc:
                return [{"error": str(exc)}]
        else:
            return [{"error": "crt.sh inaccessible (timeout)"}]

        seen: set[str] = set()
        results: list[dict] = []
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if not name or domain not in name or name in seen:
                    continue
                seen.add(name)
                issuer_raw = entry.get("issuer_name", "")
                issuer_org = next(
                    (p.strip()[2:] for p in issuer_raw.split(",")
                     if p.strip().startswith("O=")),
                    issuer_raw[:60],
                )
                results.append({
                    "subdomain":     name,
                    "issuer":        issuer_org,
                    "not_before":    entry.get("not_before", "")[:10],
                    "not_after":     entry.get("not_after",  "")[:10],
                    "serial_number": entry.get("serial_number", ""),
                })
        return results
