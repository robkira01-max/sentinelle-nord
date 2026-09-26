"""Collecteur WordPress — détection, version, utilisateurs, plugins, xmlrpc."""
import re
import warnings
from concurrent.futures import ThreadPoolExecutor

import requests
from collectors.base import BaseCollector
from core.normalizer import make_result

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_HDRS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Plugins courants à sonder via readme.txt
_PLUGINS = [
    "woocommerce", "elementor", "contact-form-7", "wordpress-seo",
    "jetpack", "akismet", "wordfence", "wpforms-lite", "really-simple-ssl",
    "updraftplus", "wp-super-cache", "loginizer", "string-locator",
    "wp-file-manager", "advanced-custom-fields", "revslider", "gravityforms",
    "yoast-seo", "all-in-one-seo-pack", "polylang", "wpml",
    "wp-rocket", "litespeed-cache", "w3-total-cache",
    "duplicator", "all-in-one-wp-migration",
    "wp-mail-smtp", "tablepress", "ninja-forms", "forminator",
    "the-events-calendar", "tribe-events-calendar",
    "wp-optimize", "smush", "imagify",
    "limit-login-attempts-reloaded", "google-sitemap-generator",
    "redirection", "broken-link-checker",
    "custom-post-type-ui", "acf-extended",
    "rank-math", "schema-and-structured-data-for-wp",
    "cookie-notice", "gdpr-cookie-compliance",
    "backupwordpress", "velvet-blues-update-urls",
    "health-check", "debug-bar", "query-monitor",
]

_SENSITIVE = {
    "/.env":                    "Variables d'environnement exposées",
    "/wp-content/debug.log":    "Log de débogage WordPress",
    "/wp-config.php.bak":       "Backup credentials BDD",
    "/wp-config.php~":          "Backup credentials BDD",
    "/readme.html":             "Expose la version WordPress",
    "/license.txt":             "Expose la version WordPress",
    "/.htaccess":               "Règles serveur Apache",
}


class WordpressCollector(BaseCollector):
    source   = "wordpress"
    category = "cms"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "url")

    def collect(self, target: str) -> dict:
        domain = target.split("/")[0] if "/" in target else target
        base   = f"https://{domain}"

        result = {
            "is_wordpress":      False,
            "version":           None,
            "users":             [],
            "xmlrpc":            "non vérifié",
            "plugins":           [],
            "api_namespaces":    [],
            "sensitive_files":   {},
            "directory_listing": [],
        }

        if not self._detect_wp(base, result):
            return make_result(self.source, self.category, result)

        self._get_version(base, result)
        self._get_users(base, result)
        self._get_api_namespaces(base, result)
        self._check_xmlrpc(base, result)
        self._enumerate_plugins(base, result)
        self._check_sensitive(base, result)

        return make_result(self.source, self.category, result)

    # ── helpers privés ─────────────────────────────────────────────

    def _detect_wp(self, base: str, result: dict) -> bool:
        try:
            r = requests.get(base, timeout=10, headers=_HDRS, verify=False)
            if any(kw in r.text.lower()
                   for kw in ("wp-content", "wp-json", "wordpress", "/wp-includes")):
                result["is_wordpress"] = True
                return True
        except Exception:
            pass

        try:
            r = requests.get(f"{base}/wp-login.php", timeout=8, headers=_HDRS,
                             verify=False, allow_redirects=False)
            if r.status_code in (200, 302):
                result["is_wordpress"] = True
                return True
        except Exception:
            pass

        return False

    def _get_version(self, base: str, result: dict) -> None:
        for path in ("/readme.html", "/license.txt"):
            try:
                r = requests.get(f"{base}{path}", timeout=8, headers=_HDRS,
                                 verify=False)
                if r.status_code == 200 and "wordpress" in r.text.lower():
                    m = re.search(r"version\s+(\d+\.\d+[\.\d]*)", r.text.lower())
                    if m:
                        result["version"] = m.group(1)
                        return
            except Exception:
                pass

        # Fallback : generator meta tag
        try:
            r = requests.get(base, timeout=10, headers=_HDRS, verify=False)
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+wordpress\s+([\d.]+)',
                          r.text, re.IGNORECASE)
            if m:
                result["version"] = m.group(1)
        except Exception:
            pass

    def _get_users(self, base: str, result: dict) -> None:
        try:
            r = requests.get(f"{base}/wp-json/wp/v2/users", timeout=8,
                             headers=_HDRS, verify=False)
            if r.status_code == 200:
                users = r.json()
                result["users"] = [
                    {"id": u.get("id"), "slug": u.get("slug"), "name": u.get("name")}
                    for u in users if isinstance(u, dict)
                ]
        except Exception:
            pass

    def _get_api_namespaces(self, base: str, result: dict) -> None:
        try:
            r = requests.get(f"{base}/wp-json/", timeout=8, headers=_HDRS,
                             verify=False)
            if r.status_code == 200:
                result["api_namespaces"] = r.json().get("namespaces", [])
        except Exception:
            pass

    def _check_xmlrpc(self, base: str, result: dict) -> None:
        try:
            r = requests.head(f"{base}/xmlrpc.php", timeout=8, headers=_HDRS,
                              verify=False)
            if r.status_code == 404:
                result["xmlrpc"] = "ABSENT (404)"
            elif r.status_code in (200, 405):
                payload = ('<?xml version="1.0"?><methodCall>'
                           '<methodName>system.listMethods</methodName>'
                           '<params></params></methodCall>')
                r2 = requests.post(
                    f"{base}/xmlrpc.php", data=payload, timeout=8,
                    verify=False, headers={**_HDRS, "Content-Type": "text/xml"},
                )
                if r2.status_code == 200 and "methodResponse" in r2.text:
                    result["xmlrpc"] = "ACTIF — brute-force possible"
                else:
                    result["xmlrpc"] = f"HTTP {r.status_code}"
            else:
                result["xmlrpc"] = f"HTTP {r.status_code}"
        except Exception as exc:
            result["xmlrpc"] = f"erreur: {exc}"

    def _enumerate_plugins(self, base: str, result: dict) -> None:
        def _check(plugin: str) -> dict | None:
            try:
                url = f"{base}/wp-content/plugins/{plugin}/readme.txt"
                r = requests.get(url, timeout=6, headers=_HDRS, verify=False)
                if r.status_code == 200 and len(r.text) > 50:
                    m = re.search(r"stable tag:\s*([^\s\n\r]+)",
                                  r.text, re.IGNORECASE)
                    version = m.group(1).strip() if m else "inconnue"
                    return {"plugin": plugin, "version": version}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            result["plugins"] = [p for p in pool.map(_check, _PLUGINS) if p]

    def _check_sensitive(self, base: str, result: dict) -> None:
        for path, desc in _SENSITIVE.items():
            try:
                r = requests.get(f"{base}{path}", timeout=6, headers=_HDRS,
                                 verify=False, allow_redirects=False)
                if r.status_code != 404:
                    result["sensitive_files"][path] = {
                        "status": r.status_code, "desc": desc,
                    }
                    if path == "/wp-content/uploads/" and "Index of" in r.text:
                        result["directory_listing"].append(path)
            except Exception:
                pass
