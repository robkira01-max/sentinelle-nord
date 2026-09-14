"""Collecteur WHOIS."""
import whois as whois_lib
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_whois


class WhoisCollector(BaseCollector):
    source = "whois"
    category = "whois"

    def supports(self) -> bool:
        return self.target_kind == "domain"

    def collect(self, target: str) -> dict:
        try:
            raw = whois_lib.whois(target)
            data = raw if isinstance(raw, dict) else dict(raw)
        except Exception as exc:  # noqa: BLE001
            return make_result(self.source, self.category, {}, error=str(exc))
        return make_result(self.source, self.category, normalize_whois(data))
