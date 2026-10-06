"""Configuration gunicorn — production."""
import multiprocessing
import os

# Workers : 2 × CPUs + 1 (recommandation gunicorn)
workers = int(os.getenv("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"
threads = int(os.getenv("GUNICORN_THREADS", "1"))

bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
keepalive = 5

# Logging
accesslog = "-"   # stdout
errorlog  = "-"   # stderr
loglevel  = os.getenv("LOG_LEVEL", "info")

# Sécurité
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
proxy_protocol = False
limit_request_line = 4094
limit_request_fields = 100
