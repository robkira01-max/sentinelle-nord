FROM python:3.11-slim AS base

WORKDIR /app

# Dépendances système (WeasyPrint + psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Image finale ──────────────────────────────────────────────────────────────
FROM base AS app

WORKDIR /app
COPY . .

# Utilisateur non-root
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser \
    && chown -R appuser:appgroup /app
USER appuser

EXPOSE 8000

# Gunicorn — prod
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
