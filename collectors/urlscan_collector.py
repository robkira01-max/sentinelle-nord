"""Collecteur URLScan.io — recherche passive avec cache TTL."""
import requests
from config import Config
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_urlscan
from cache import get_cached, set_cached

_NS = "urlscan"


class UrlscanCollector(BaseCollector):
    source = "urlscan"
    category = "http"
    _BASE = "https://urlscan.io/api/v1/search/"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "ip", "url")

    def collect(self, target: str) -> dict:
        if not Config.URLSCAN_API_KEY:
            return make_result(self.source, self.category, {},
                               error="URLSCAN_API_KEY not configured")

        cached = get_cached(_NS, target)
        if cached:
            return make_result(self.source, self.category, cached)

        try:
            r = requests.get(
                self._BASE,
                headers={"api-key": Config.URLSCAN_API_KEY},
                params={"q": f"domain:{target}", "size": 10},
                timeout=Config.HTTP_TIMEOUT,
            )
            r.raise_for_status()
            first = r.json().get("results", [{}])[0]
            data = normalize_urlscan(first)
        except Exception as exc:  # noqa: BLE001
            return make_result(self.source, self.category, {}, error=str(exc))

        set_cached(_NS, data, Config.CACHE_TTL, target)
        return make_result(self.source, self.category, data)
