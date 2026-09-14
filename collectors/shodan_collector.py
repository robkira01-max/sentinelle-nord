"""Collecteur Shodan — host lookup avec cache TTL."""
import socket
import requests
from config import Config
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_shodan
from cache import get_cached, set_cached

_NS = "shodan"


class ShodanCollector(BaseCollector):
    source = "shodan"
    category = "ports"
    _BASE = "https://api.shodan.io/shodan/host/"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "ip")

    def _resolve(self, target: str) -> str:
        return target if self.target_kind == "ip" else socket.gethostbyname(target)

    def collect(self, target: str) -> dict:
        if not Config.SHODAN_API_KEY:
            return make_result(self.source, self.category, {},
                               error="SHODAN_API_KEY not configured")

        cached = get_cached(_NS, target)
        if cached:
            return make_result(self.source, self.category, cached)

        try:
            ip = self._resolve(target)
            r = requests.get(
                f"{self._BASE}{ip}",
                params={"key": Config.SHODAN_API_KEY},
                timeout=Config.HTTP_TIMEOUT,
            )
            r.raise_for_status()
            data = normalize_shodan(r.json())
        except Exception as exc:  # noqa: BLE001
            return make_result(self.source, self.category, {}, error=str(exc))

        set_cached(_NS, data, Config.CACHE_TTL, target)
        return make_result(self.source, self.category, data)
