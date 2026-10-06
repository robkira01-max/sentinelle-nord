# Sentinelle_Nord — Guide de développement Claude Code

## Description du projet

Plateforme interne d'audit OSINT et de surveillance arctique Canada.
**Positionnement** : deux modules distincts —
- **Module A** : exposition cyber du Nord canadien (surface d'attaque passive des infrastructures nordiques)
- **Module B** : conscience du domaine arctique (démonstrateur de fusion de sources ouvertes — **pas** un système opérationnel)

**Statut** : v1.6 — 206 tests · CPCSC Niveau 1 auto-évaluation · Dernière session : P5 (2026-10-06)

---

## ⚠️ RÈGLES DE SÉCURITÉ — NON-NÉGOCIABLES

1. **Jamais de secret dans ce fichier** : ni mot de passe, ni clé API, ni token.
   Ce fichier est lu par chaque session Claude Code. Placeholders uniquement (`$FLASK_SECRET_KEY`, `$SHODAN_API_KEY`, etc.).
2. **Credentials dans `.env` uniquement** — jamais dans le code ni dans git.
3. **Données de test fictives uniquement** — aucune vraie cible, aucune vraie IP client dans les tests.
4. **Collecte active ≠ collecte passive.** Tout collector qui envoie des requêtes vers une cible est **actif**, quelle que soit leur légèreté.
   - `backup_collector` (30 requêtes HEAD) = **actif**
   - `wordpress_collector` (énumération d'utilisateurs) = **actif**
   - En contexte non autorisé : risque art. 342.1 Code criminel (non avis juridique).
   - **Règle** : les collectors actifs exigent une autorisation écrite du client, avec contrôle dans le code (flag `authorized=True` ou équivalent).
5. **Tests avant merge** — `pytest tests/ -v` doit passer entièrement.
6. **AuditLog** pour toute action sensible (scan, export PDF, accès utilisateur).

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Framework | Flask 3.0.3 |
| ORM | Flask-SQLAlchemy 3.1.1 (SQLAlchemy 2.x) |
| Auth | Flask-Login 0.6.3 + RBAC (admin/analyst/readonly) |
| Rate limiting | Flask-Limiter 3.9.0 (5/min login, 10/min scan) |
| PDF | WeasyPrint 70.0 |
| Base de données | SQLite prototype → **PostgreSQL requis avant toute présentation MDN** |
| Scheduler | APScheduler 3.10.4 (collecte toutes les heures) |
| Cartographie | Folium |
| Forms | Flask-WTF 1.2.2 |

> SQLite + serveur Flask de développement + Kali en VirtualBox = prototype démontrable,
> **pas** un produit présentable à la Défense. Migration PostgreSQL + Docker + gunicorn requise.

---

## Structure du projet

```
osint_ti/
├── app.py                    # factory create_app()
├── extensions.py             # login_manager + limiter singletons
├── models.py                 # User (UserMixin) + Scan + Finding + Target
├── config.py                 # Settings depuis .env
├── database.py               # init_db()
├── cache.py                  # Cache simple
├── .env                      # FLASK_SECRET_KEY, API keys — NE PAS COMMITER
├── auth/
│   └── routes.py             # Blueprint /auth — login/logout/users RBAC
├── api/
│   ├── routes.py             # Blueprint / — dashboard + /api/* + /north/*
│   └── templates/            # dashboard.html, login.html, users.html
├── collectors/
│   ├── base.py               # Classe de base CollectorBase
│   ├── dns_collector.py      # DNS passif ✅
│   ├── http_collector.py     # Headers HTTP, tech stack ✅ passif
│   ├── whois_collector.py    # WHOIS ✅ passif
│   ├── urlscan_collector.py  # URLScan.io API ✅ passif
│   ├── cve_collector.py      # CVE (NVD API) ✅ passif
│   ├── censys_collector.py   # Censys API ✅ passif
│   ├── shodan_collector.py   # Shodan API ✅ passif
│   ├── crtsh_collector.py    # Certificate Transparency (crt.sh) ✅ passif
│   ├── backup_collector.py   # 30 requêtes HEAD vers la cible ⚠️ ACTIF
│   └── wordpress_collector.py# Énumération utilisateurs WP ⚠️ ACTIF
├── arctic/
│   ├── adsb_engine.py        # ADS-B 60-90°N (OpenSky) ⚠️ couverture à valider
│   ├── ais_engine.py         # AIS maritime (AISHub) ⚠️ AIS terrestre quasi absent >80°N
│   ├── satellite_engine.py   # Passages satellites polaires
│   ├── weather_engine.py     # Météo stations arctiques
│   ├── ice_engine.py         # Glace marine (NSIDC)
│   ├── infra_engine.py       # Infrastructure critique nordique
│   └── geo_engine.py         # Géolocalisation
├── core/
│   ├── aggregator.py         # Agrégation résultats multi-collectors
│   └── normalizer.py         # Normalisation findings
├── reporting/
│   ├── pdf_report.py         # Rapport OSINT WeasyPrint (4 sections)
│   ├── risk_score.py         # Score pondéré — voir section Score ci-dessous
│   ├── generator.py          # Orchestrateur rapport
│   └── user_manual.py        # Manuel utilisateur PDF (10 chapitres)
├── monitoring/delta.py       # Détection changements entre scans
├── streaming/scheduler.py    # APScheduler collecte horaire
├── scripts/create_admin.py   # Seed admin CLI
└── tests/
    ├── conftest.py
    ├── test_api.py
    ├── test_arctic.py
    ├── test_auth.py
    └── test_core.py
```

---

## RBAC — Rôles

| Rôle | Accès |
|------|-------|
| `admin` | Tout + gestion utilisateurs |
| `analyst` | Scan + rapports + arctic |
| `readonly` | Rapports + arctic uniquement |

Compte admin → défini dans `.env` (jamais dans ce fichier).
Pour réinitialiser : `python3 scripts/create_admin.py`

---

## Score de risque

**Formule** : `0.6 × max(CVSS_pondéré) + 0.4 × mean(CVSS_pondéré)` — plafonné à 10

**Multiplicateurs** : KEV×1.5 · âge>2ans×1.2 · email_exposé×1.1 · endpoint_exposé×1.2 · 0auth×1.3 · EOL×1.1

> ⚠️ Les multiplicateurs sont cumulables — le score peut dépasser 10 sans plafond.
> **À corriger** : plafonner à 10 et ajouter EPSS (exploitabilité en conditions réelles).
> Sans plafond, les grades A+ à F perdent leur sens.

**Grades** : A+(0–2) · A(2–3.5) · B(3.5–5) · C(5–6.5) · D(6.5–8) · F(8–10)

---

## Sources arctiques — Validation requise

| Source | Statut | Problème |
|--------|--------|---------|
| OpenSky (ADS-B) | ⚠️ à valider | Couverture terrestre médiocre >80°N ; conditions d'usage commercial à vérifier |
| AISHub (AIS) | ⚠️ à valider | AIS terrestre quasi absent dans l'Arctique (besoin de satellite) ; licence commerciale ? |
| NSIDC (glace) | ✅ données ouvertes | — |

> Ne pas promettre de couverture arctique sans avoir validé les sources.
> Pour un usage opérationnel : AIS satellite (Spire, exactEarth), géolocalisation RF (HawkEye 360).

---

## API REST (15 endpoints)

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard HTML |
| `POST /api/scan` | Scan OSINT (analyst+) — collectors actifs exigent autorisation |
| `GET /api/targets` | Liste cibles |
| `GET /api/scan/<id>` | Résultat scan JSON |
| `GET /api/report/<id>` | Rapport PDF |
| `GET /north/adsb` | Trafic aérien arctique |
| `GET /north/ais` | Trafic maritime arctique |
| `GET /north/satellite` | Passages satellites polaires |
| `GET /north/weather` | Météo stations arctiques |
| `GET /north/ice` | Glace marine NSIDC |
| `GET /north/infra` | Infrastructure critique nordique |
| `GET /north/map` | Carte arctique HTML (Folium) |
| `GET /auth/login` | Page login |
| `POST /auth/login` | Authentification |
| `GET /auth/users` | Gestion users (admin) |

---

## Lancement

```bash
cd /home/kali/osint_ti/
source .venv/bin/activate

# Normal
python3 app.py                      # http://0.0.0.0:5000

# Sans scheduler (dev/test)
SCHEDULER_ENABLED=false python3 app.py

# Tests
pytest tests/ -v                    # 125 tests
```

Compte admin : voir `.env` (jamais dans ce fichier).

---

## Variables d'environnement (.env)

| Variable | Description |
|----------|-------------|
| `FLASK_SECRET_KEY` | Clé session Flask — générer : `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `SHODAN_API_KEY` | Shodan API |
| `CENSYS_API_ID` | Censys ID |
| `CENSYS_API_SECRET` | Censys Secret |
| `URLSCAN_API_KEY` | URLScan.io |
| `SCHEDULER_ENABLED` | `true`/`false` |
| `ADMIN_PASSWORD` | Mot de passe admin — à générer, jamais « admin » ou par défaut |

---

## Partage avec collaborateur

- **Recommandé** : Tailscale (VPN mesh persistant, accès restreint)
- ngrok : URL HTTPS publique 2h — utiliser uniquement avec authentification forte et après changement du mot de passe admin par défaut
- VirtualBox Port Forwarding : TCP host:5000 → guest 10.0.2.15:5000

---

## Orientation marché (évaluation 2026-10-04)

**Positionnement recommandé** : séparer clairement les deux modules.
- Module A (surface d'attaque passive) : CPCSC niveau 1 auto-évaluation, sous-traitance grands intégrateurs, programmes IDEaS MDN
- Module B (arctique) : démonstrateur de fusion sources ouvertes, **pas** système opérationnel

**Canal d'entrée réaliste** : programmes d'innovation MDN (IDEaS), partenariats entreprises autochtones (NOSH), rôle de sous-traitant. La vente directe à l'Armée en solo est peu réaliste.

**Avant toute présentation MDN** :
- Corriger la doctrine passif/actif
- Passer à PostgreSQL + Docker + gunicorn
- Auto-évaluation CPCSC niveau 1 du projet lui-même

---

## Directives priorisées (évaluation 2026-10-04)

| Priorité | Action | Statut |
|----------|--------|--------|
| 1 | Changer le mot de passe admin, retirer tout accès ngrok par défaut | À faire (non codable ici) |
| 2 | Contrôle d'autorisation sur collectors actifs (backup, wordpress) | ✅ 2026-10-04 — `requires_authorization=True`, `authorized=True` requis dans le payload POST `/api/scan` |
| 3 | Plafonner le score à 10, ajouter EPSS, documenter la méthode | ✅ 2026-10-04 — EPSS dans `Finding`, multiplicateurs ×1.2/×1.5, enrichissement FIRST.org dans `cve_collector`, cap confirmé `min(s,10)` |
| 4 | PostgreSQL + Docker + gunicorn (requis avant MDN) | ✅ 2026-10-05 — Dockerfile, docker-compose.yml, gunicorn.conf.py, wsgi.py, 174/174 tests |
| 5 | CPCSC niveau 1 auto-évaluation | ✅ 2026-10-06 — 17 contrôles, score ≈70%, /compliance/cpcsc, 206/206 tests |
| 6 | Corrélation d'actifs par organisation (domaines, certificats, ASN) | Non démarré |
| 7 | Valider sources arctiques (licences, couverture réelle) | Non démarré |
| 8 | STIX/TAXII, export SIEM, rapports FR/EN | ✅ 2026-10-04 — `build_html(lang="fr"|"en")`, `_LABELS` dict, `--lang` CLI, 5 tests bilingues |

---

## PDFs générés

Transférer vers `/media/sf_Kali-share/OSINT 2026/` après chaque génération.
