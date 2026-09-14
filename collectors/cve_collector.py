"""Collecteur CVE — NVD API 2.0.

Le keyword est configurable via CVE_KEYWORD dans .env.
Fallback : premier label du domaine (ex: "apache" pour apache.org).
"""
import requests
from config import Config
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_cve
from cache import get_cached, set_cached

_NS = "cve"
_CVE_TTL = 3600 * 6  # cache 6h (NVD rate-limit strict)


class CVECollector(BaseCollector):
    source = "cve"
    category = "vulns"
    _BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def supports(self) -> bool:
        return self.target_kind == "domain"

    def _keyword(self, target: str) -> str:
        if Config.CVE_KEYWORD:
            return Config.CVE_KEYWORD
        return target.split(".")[0]

    def collect(self, target: str) -> dict:
        keyword = self._keyword(target)

        cached = get_cached(_NS, keyword)
        if cached:
            return make_result(self.source, self.category, cached)

        try:
            r = requests.get(
                self._BASE,
                params={"keywordSearch": keyword, "resultsPerPage": 20},
                timeout=Config.HTTP_TIMEOUT,
            )
            r.raise_for_status()
            data = normalize_cve(r.json())
        except Exception as exc:  # noqa: BLE001
            return make_result(self.source, self.category, {}, error=str(exc))

        set_cached(_NS, data, _CVE_TTL, keyword)
        return make_result(self.source, self.category, data)
