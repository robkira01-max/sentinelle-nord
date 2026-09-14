"""Collecteur DNS — via dnspython."""
import dns.resolver
from collectors.base import BaseCollector
from core.normalizer import make_result, normalize_dns

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSCollector(BaseCollector):
    source = "dns"
    category = "dns"

    def supports(self) -> bool:
        return self.target_kind == "domain"

    def collect(self, target: str) -> dict:
        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=5)
                records[rtype] = [r.to_text() for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception as exc:  # noqa: BLE001
                records[rtype] = [f"error: {exc}"]
        return make_result(self.source, self.category, normalize_dns(records))
