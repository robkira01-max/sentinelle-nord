"""Collecteur Censys — API v2 host view avec cache TTL."""
import socket
import requests
from requests.auth import HTTPBasicAuth
from config import Config
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_censys
from cache import get_cached, set_cached

_NS = "censys"


class CensysCollector(BaseCollector):
    source = "censys"
    category = "ports"
    _BASE = "https://search.censys.io/api/v2/hosts/"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "ip")

    def _resolve(self, target: str) -> str:
        return target if self.target_kind == "ip" else socket.gethostbyname(target)

    def collect(self, target: str) -> dict:
        if not (Config.CENSYS_API_ID and Config.CENSYS_API_SECRET):
            return make_result(self.source, self.category, {},
                               error="CENSYS credentials not configured")

        cached = get_cached(_NS, target)
        if cached:
            return make_result(self.source, self.category, cached)

        try:
            ip = self._resolve(target)
            r = requests.get(
                f"{self._BASE}{ip}",
                auth=HTTPBasicAuth(Config.CENSYS_API_ID, Config.CENSYS_API_SECRET),
                timeout=Config.HTTP_TIMEOUT,
            )
            r.raise_for_status()
            data = normalize_censys(r.json().get("result", {}))
        except Exception as exc:  # noqa: BLE001
            return make_result(self.source, self.category, {}, error=str(exc))

        set_cached(_NS, data, Config.CACHE_TTL, target)
        return make_result(self.source, self.category, data)
