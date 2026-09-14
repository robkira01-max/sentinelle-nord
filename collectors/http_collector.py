"""Collecteur HTTP — headers sécurité, SSL/TLS, DMARC, SPF, redirections."""
import socket
import ssl
import datetime
import dns.resolver
import requests
from collectors.base import BaseCollector
from core.normalizer import make_result

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


class HTTPCollector(BaseCollector):
    source = "http"
    category = "http"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "url")

    def collect(self, target: str) -> dict:
        domain = target.split("/")[0] if "/" in target else target
        data: dict = {
            "domain": domain,
            "headers": {},
            "missing_headers": [],
            "ssl": {},
            "dmarc": None,
            "spf": None,
            "redirect_chain": [],
        }
        errors = []

        # ── HTTP headers + redirect chain ──────────────────────────
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=8,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                data["status_code"] = resp.status_code
                data["final_url"] = resp.url
                data["server"] = resp.headers.get("server", "")
                data["x_powered_by"] = resp.headers.get("x-powered-by", "")
                data["redirect_chain"] = [str(r.url) for r in resp.history]

                lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                data["headers"] = {h: lower_headers.get(h)
                                   for h in SECURITY_HEADERS}
                data["missing_headers"] = [h for h in SECURITY_HEADERS
                                           if not lower_headers.get(h)]
                break
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{scheme}: {exc}")

        # ── SSL/TLS certificate ─────────────────────────────────────
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=5),
                server_hostname=domain,
            ) as s:
                cert = s.getpeercert()
                not_after = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (not_after - datetime.datetime.utcnow()).days
                data["ssl"] = {
                    "issuer":    dict(x[0] for x in cert.get("issuer", [])),
                    "subject":   dict(x[0] for x in cert.get("subject", [])),
                    "not_after": cert["notAfter"],
                    "days_left": days_left,
                    "expired":   days_left < 0,
                    "sans":      [v for _, v in cert.get("subjectAltName", [])],
                    "version":   cert.get("version"),
                }
        except Exception as exc:  # noqa: BLE001
            data["ssl"] = {"error": str(exc)}

        # ── DMARC ───────────────────────────────────────────────────
        try:
            ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            for r in ans:
                txt = r.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    data["dmarc"] = txt
                    break
        except Exception:
            data["dmarc"] = None

        # ── SPF ─────────────────────────────────────────────────────
        try:
            ans = dns.resolver.resolve(domain, "TXT", lifetime=5)
            for r in ans:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    data["spf"] = txt
                    break
        except Exception:
            data["spf"] = None

        return make_result(
            self.source, self.category, data,
            error="; ".join(errors) if errors else None,
        )
