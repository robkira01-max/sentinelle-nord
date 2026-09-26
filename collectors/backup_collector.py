"""Collecteur Backup Surface — .git, .env, fichiers de sauvegarde, staging."""
import warnings
from concurrent.futures import ThreadPoolExecutor

import requests
from collectors.base import BaseCollector
from core.normalizer import make_result

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_HDRS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

_BACKUP_FILE_PATHS = [
    "/backup.zip",         "/backup.tar.gz",       "/backup.sql",
    "/backup.sql.gz",      "/db_backup.sql",        "/database.sql",
    "/database.sql.gz",    "/db.sql",               "/dump.sql",
    "/data.sql",           "/export.sql",           "/site.tar.gz",
    "/www.zip",            "/public_html.zip",       "/htdocs.zip",
    "/files.tar.gz",       "/uploads.zip",
    "/.env.bak",           "/.env.old",             "/.env.backup",
    "/.env",               "/config.php.bak",       "/config.php.old",
    "/wp-config.php.bak",  "/wp-config.php~",       "/wp-config.php.old",
    "/.git/config",        "/.git/HEAD",            "/.svn/entries",
    "/web.config.bak",     "/settings.php.bak",     "/configuration.php.bak",
]

_BACKUP_SUBDOMAIN_HINTS = {
    "backup", "bkp", "bak", "archive", "archives", "restore",
    "snapshot", "old", "legacy", "db-backup", "data-backup",
    "file-backup", "export", "exports", "dump", "recovery",
}

_STAGING_HINTS = {"staging", "dev", "test", "preprod", "pre-prod", "uat", "qa", "demo"}


class BackupCollector(BaseCollector):
    source   = "backup"
    category = "exposure"

    def supports(self) -> bool:
        return self.target_kind in ("domain", "url")

    def collect(self, target: str) -> dict:
        domain = target.split("/")[0] if "/" in target else target

        exposed  = self._probe_files(domain)
        robots   = self._check_robots(domain)
        git_flag = any(
            f["path"] in ("/.git/config", "/.git/HEAD") and f["status"] == 200
            for f in exposed
        )

        data = {
            "exposed_files":  exposed,
            "robots_disallow": robots,
            "git_exposed":    git_flag,
            "rsync_exposed":  False,       # enrichi par shodan_collector si disponible
            "summary": {
                "total_exposed": len(exposed),
                "critical":      sum(1 for f in exposed if f["risk"] == "CRITIQUE"),
                "high":          sum(1 for f in exposed if f["risk"] == "ÉLEVÉ"),
                "git_exposed":   git_flag,
            },
        }
        return make_result(self.source, self.category, data)

    # ── helpers privés ─────────────────────────────────────────────

    def _probe_files(self, domain: str) -> list[dict]:
        def _check(path: str) -> dict | None:
            try:
                is_git = path.startswith("/.git")
                if is_git:
                    r = requests.get(
                        f"https://{domain}{path}",
                        timeout=8, headers=_HDRS, verify=False,
                        allow_redirects=False,
                    )
                    if r.status_code == 200:
                        content = r.text.strip()
                        # Validation anti-faux-positifs SPA
                        valid = (
                            content.startswith("ref:") or
                            content.startswith("refs/") or
                            "[core]" in content or
                            (len(content) == 40 and
                             all(c in "0123456789abcdef" for c in content))
                        )
                        if not valid:
                            return None
                    elif r.status_code == 403:
                        return {"path": path, "status": 403,
                                "size": "?", "risk": "MOYEN"}
                    else:
                        return None
                    size  = str(len(r.content))
                    ctype = r.headers.get("content-type", "text/plain")[:60]
                    risk  = "CRITIQUE"
                else:
                    r = requests.head(
                        f"https://{domain}{path}",
                        timeout=6, headers=_HDRS, verify=False,
                        allow_redirects=False,
                    )
                    if r.status_code in (404, 410):
                        return None
                    size  = r.headers.get("content-length", "?")
                    ctype = r.headers.get("content-type", "")[:60]
                    if path in ("/.env", "/.env.bak", "/.env.old", "/.env.backup"):
                        risk = "CRITIQUE"
                    elif path.endswith((".sql", ".sql.gz", ".sql.bz2")):
                        risk = "CRITIQUE"
                    elif path.endswith((".zip", ".tar.gz", ".bak", ".env")):
                        risk = "ÉLEVÉ"
                    else:
                        risk = "MOYEN"

                return {
                    "path":         path,
                    "status":       r.status_code,
                    "size":         size,
                    "content_type": ctype,
                    "risk":         risk,
                }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(_check, _BACKUP_FILE_PATHS))
        return [r for r in results if r is not None]

    def _check_robots(self, domain: str) -> list[str]:
        backup_kw = ["backup", "bkp", "archive", "dump", "export", "old", "restore"]
        found: list[str] = []
        try:
            r = requests.get(
                f"https://{domain}/robots.txt",
                timeout=8, headers=_HDRS, verify=False,
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip().lower()
                        if any(kw in path for kw in backup_kw):
                            found.append(line)
        except Exception:
            pass
        return found
