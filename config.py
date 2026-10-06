"""Configuration centralisée — lit les variables d'environnement."""
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


class Config:
    # Flask
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
    ENV = os.getenv("FLASK_ENV", "development")
    HOST = os.getenv("FLASK_HOST", "127.0.0.1")
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # DB / cache
    # Convertit postgres:// → postgresql:// (compatibilité Heroku/Railway)
    _raw_db = os.getenv("DATABASE_URL", "sqlite:///osint.db")
    DATABASE_URL = _raw_db.replace("postgres://", "postgresql://", 1) if _raw_db.startswith("postgres://") else _raw_db
    CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))

    # Clés API
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

    # CVE keyword explicite (sinon fallback = premier label du domaine)
    CVE_KEYWORD = os.getenv("CVE_KEYWORD", "")

    # Activation collectors
    ENABLED_COLLECTORS: dict[str, bool] = {
        "dns":       _bool("ENABLE_DNS",       "true"),
        "http":      _bool("ENABLE_HTTP",      "true"),
        "whois":     _bool("ENABLE_WHOIS",     "true"),
        "urlscan":   _bool("ENABLE_URLSCAN",   "false"),
        "shodan":    _bool("ENABLE_SHODAN",    "false"),
        "censys":    _bool("ENABLE_CENSYS",    "false"),
        "cve":       _bool("ENABLE_CVE",       "true"),
        "crtsh":     _bool("ENABLE_CRTSH",     "true"),
        "wordpress": _bool("ENABLE_WORDPRESS", "true"),
        "backup":    _bool("ENABLE_BACKUP",    "true"),
    }

    HTTP_TIMEOUT = 10
