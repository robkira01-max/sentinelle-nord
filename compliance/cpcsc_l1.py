"""CPCSC Level 1 — auto-évaluation du projet Sentinelle_Nord.

Programme canadien de certification en cybersécurité (CPCSC) Niveau 1
= 17 pratiques de base d'hygiène cyber issues de NIST SP 800-171 / FAR 52.204-21.

Référence : Travaux publics et Services gouvernementaux Canada (TPSGC),
Programme de cybersécurité pour les fournisseurs de défense — Niveau 1.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Literal

STATUS = Literal["IMPLEMENTED", "PARTIAL", "PROCEDURAL", "NOT_IMPLEMENTED"]
PRIORITY = Literal["HIGH", "MEDIUM", "LOW"]


@dataclass
class Control:
    id: str
    domain: str
    title: str
    description: str
    status: STATUS
    evidence: str
    gap: str = ""
    priority: PRIORITY = "MEDIUM"
    references: list[str] = field(default_factory=list)


# ── 17 contrôles CPCSC Niveau 1 ───────────────────────────────────────────────

CONTROLS: list[Control] = [
    # ── Access Control (AC) ───────────────────────────────────────────────────

    Control(
        id="AC.L1-3.1.1",
        domain="Contrôle d'accès",
        title="Accès réservé aux utilisateurs autorisés",
        description=(
            "Limiter l'accès au système aux utilisateurs autorisés, aux processus "
            "agissant au nom d'utilisateurs autorisés, et aux équipements autorisés."
        ),
        status="IMPLEMENTED",
        evidence=(
            "Flask-Login (login_required) + modèle User avec rôles admin/analyst/readonly. "
            "Toutes les routes sensibles protégées par @login_required ou @require_role."
        ),
        references=["auth/routes.py — require_role()", "models.py — ROLES"],
    ),

    Control(
        id="AC.L1-3.1.2",
        domain="Contrôle d'accès",
        title="Contrôle des transactions par rôle",
        description=(
            "Limiter l'accès du système aux types de transactions et de fonctions "
            "que les utilisateurs autorisés sont autorisés à exécuter."
        ),
        status="IMPLEMENTED",
        evidence=(
            "RBAC : admin=tout, analyst=scan+rapports+arctic, readonly=rapports+arctic. "
            "@require_role('admin','analyst') sur POST /api/scan. "
            "@require_role('admin') sur GET /auth/users."
        ),
        references=["auth/routes.py — require_role()", "api/routes.py"],
    ),

    Control(
        id="AC.L1-3.1.20",
        domain="Contrôle d'accès",
        title="Contrôle des connexions aux systèmes externes",
        description=(
            "Vérifier et contrôler/limiter les connexions aux systèmes d'information externes."
        ),
        status="PARTIAL",
        evidence=(
            "Les clés API externes (Shodan, Censys, URLScan) sont stockées dans .env. "
            "Les collectors actifs exigent authorized=True dans le payload. "
            "Docker isole le réseau app/db (P4)."
        ),
        gap=(
            "Pas de liste blanche explicite des endpoints externes autorisés. "
            "Pas de circuit breaker documenté pour chaque API tierce."
        ),
        priority="MEDIUM",
        references=["config.py — ENABLED_COLLECTORS", "collectors/base.py"],
    ),

    Control(
        id="AC.L1-3.1.22",
        domain="Contrôle d'accès",
        title="Contrôle des informations publiées",
        description=(
            "Contrôler les informations publiées ou traitées sur les systèmes "
            "accessibles au public."
        ),
        status="IMPLEMENTED",
        evidence=(
            "L'application est interne (pas de déploiement public par défaut). "
            "Toutes les routes requièrent une authentification. "
            "Le dashboard n'expose aucune donnée sans login."
        ),
        references=["app.py — login_manager", "auth/routes.py"],
    ),

    # ── Identification & Authentication (IA) ─────────────────────────────────

    Control(
        id="IA.L1-3.5.1",
        domain="Identification et authentification",
        title="Identification des utilisateurs et équipements",
        description=(
            "Identifier les utilisateurs du système, les processus agissant au nom "
            "des utilisateurs, et les équipements."
        ),
        status="IMPLEMENTED",
        evidence=(
            "Modèle User avec id, username, email, role. "
            "Chaque session est liée à un utilisateur identifié (Flask-Login)."
        ),
        references=["models.py — User", "auth/routes.py"],
    ),

    Control(
        id="IA.L1-3.5.2",
        domain="Identification et authentification",
        title="Authentification avant accès",
        description=(
            "Authentifier (ou vérifier) l'identité des utilisateurs, des processus "
            "ou des équipements avant d'autoriser l'accès."
        ),
        status="IMPLEMENTED",
        evidence=(
            "Werkzeug generate_password_hash / check_password_hash (PBKDF2-SHA256). "
            "Rate-limit login 5/min (Flask-Limiter). "
            "Session cookie HTTP-only + SameSite=Lax."
        ),
        references=["auth/routes.py — login()", "app.py — SESSION_COOKIE_*"],
    ),

    # ── Media Protection (MP) ─────────────────────────────────────────────────

    Control(
        id="MP.L1-3.8.3",
        domain="Protection des médias",
        title="Suppression sécurisée des médias",
        description=(
            "Assainir ou détruire les médias du système d'information contenant "
            "des informations avant leur élimination ou réutilisation."
        ),
        status="PROCEDURAL",
        evidence=(
            "Aucun support physique propre au projet. "
            "La base de données PostgreSQL en production doit être purgée via "
            "DROP TABLE + VACUUM FULL avant décommissionnement. "
            "Procédure à documenter dans le runbook opérationnel."
        ),
        gap=(
            "Procédure écrite de suppression sécurisée des données absente. "
            "Pas de script de purge inclus dans le projet."
        ),
        priority="LOW",
    ),

    # ── Physical Protection (PE) ──────────────────────────────────────────────

    Control(
        id="PE.L1-3.10.1",
        domain="Protection physique",
        title="Restriction de l'accès physique",
        description=(
            "Limiter l'accès physique aux systèmes d'information organisationnels, "
            "aux équipements et aux environnements d'exploitation."
        ),
        status="PROCEDURAL",
        evidence=(
            "Déployé sur Oracle Cloud Free Tier (Frankfurt) ou VirtualBox local. "
            "Contrôle physique fourni par le datacenter OCI ou la machine hôte."
        ),
        gap="Aucun contrôle d'accès physique géré par le projet lui-même.",
        priority="LOW",
    ),

    Control(
        id="PE.L1-3.10.3",
        domain="Protection physique",
        title="Accompagnement des visiteurs",
        description="Escorter les visiteurs et surveiller leur activité.",
        status="PROCEDURAL",
        evidence="Procédure organisationnelle — hors périmètre logiciel.",
        priority="LOW",
    ),

    Control(
        id="PE.L1-3.10.4",
        domain="Protection physique",
        title="Journal d'accès physique",
        description="Tenir des journaux d'audit des accès physiques.",
        status="PROCEDURAL",
        evidence="Fourni par le datacenter hôte (OCI audit logs).",
        priority="LOW",
    ),

    Control(
        id="PE.L1-3.10.5",
        domain="Protection physique",
        title="Gestion des dispositifs d'accès physique",
        description="Contrôler et gérer les dispositifs d'accès physique.",
        status="PROCEDURAL",
        evidence="Clés, badges, accès OCI — procédure organisationnelle.",
        priority="LOW",
    ),

    # ── System & Communications Protection (SC) ───────────────────────────────

    Control(
        id="SC.L1-3.13.1",
        domain="Protection des systèmes et des communications",
        title="Protection des communications aux frontières",
        description=(
            "Surveiller, contrôler et protéger les communications aux frontières "
            "externes et aux frontières internes clés."
        ),
        status="IMPLEMENTED",
        evidence=(
            "Docker Compose isole les services db/app sur un réseau interne. "
            "La base de données n'est pas exposée sur Internet (pas de port publié). "
            "Flask-Limiter limite le débit sur les endpoints sensibles."
        ),
        references=["docker-compose.yml", "extensions.py — limiter"],
    ),

    Control(
        id="SC.L1-3.13.5",
        domain="Protection des systèmes et des communications",
        title="Séparation des composants accessibles au public",
        description=(
            "Mettre en œuvre des sous-réseaux pour les composants du système "
            "accessibles au public, séparés physiquement ou logiquement des "
            "réseaux internes."
        ),
        status="IMPLEMENTED",
        evidence=(
            "docker-compose.yml : service `app` expose uniquement le port 8000, "
            "service `db` PostgreSQL accessible seulement depuis le réseau Docker interne. "
            "En production (docs/deploiement.md), Caddy TLS termine la connexion externe."
        ),
        references=["docker-compose.yml", "docker-compose.prod.yml (coffre-juridique pattern)"],
    ),

    # ── System & Information Integrity (SI) ───────────────────────────────────

    Control(
        id="SI.L1-3.14.1",
        domain="Intégrité du système et de l'information",
        title="Correction des vulnérabilités",
        description=(
            "Identifier, signaler et corriger en temps opportun les défauts du "
            "système d'information."
        ),
        status="PARTIAL",
        evidence=(
            "requirements.txt avec versions pinned. "
            "GitHub Actions CI/CD (P5 — T5.7) lint + tests sur push. "
            "Pas encore de scan automatique des dépendances (Dependabot ou Safety)."
        ),
        gap=(
            "Aucun outil de scan de dépendances automatisé (Dependabot / pip-audit). "
            "Procédure de patch management non documentée."
        ),
        priority="HIGH",
        references=[".github/workflows/ci.yml", "requirements.txt"],
    ),

    Control(
        id="SI.L1-3.14.2",
        domain="Intégrité du système et de l'information",
        title="Protection contre le code malveillant",
        description=(
            "Fournir une protection contre le code malveillant aux endroits "
            "appropriés."
        ),
        status="IMPLEMENTED",
        evidence=(
            "Validation des entrées utilisateur (Flask-WTF CSRF, parsing strict). "
            "RBAC bloque les actions non autorisées. "
            "Rate-limit sur login (5/min) et scan (10/min). "
            "Collectors actifs exigent authorized=True explicite."
        ),
        references=["auth/routes.py", "api/routes.py", "collectors/base.py"],
    ),

    Control(
        id="SI.L1-3.14.4",
        domain="Intégrité du système et de l'information",
        title="Mise à jour des mécanismes de protection",
        description=(
            "Mettre à jour les mécanismes de protection contre le code malveillant "
            "lorsque de nouvelles versions sont disponibles."
        ),
        status="PARTIAL",
        evidence=(
            "requirements.txt avec contraintes de version minimale. "
            "CI/CD reconstruit l'image Docker à chaque push (pull latest base image)."
        ),
        gap=(
            "Pas de Dependabot ni de pip-audit dans la CI. "
            "Procédure de revue mensuelle des dépendances absente."
        ),
        priority="MEDIUM",
        references=["requirements.txt", ".github/workflows/ci.yml"],
    ),

    Control(
        id="SI.L1-3.14.5",
        domain="Intégrité du système et de l'information",
        title="Analyse périodique et temps réel",
        description=(
            "Effectuer des analyses périodiques du système d'information et des "
            "analyses en temps réel des fichiers provenant de sources externes."
        ),
        status="IMPLEMENTED",
        evidence=(
            "La plateforme elle-même effectue des scans OSINT passifs périodiques "
            "(APScheduler toutes les heures) sur les domaines cibles. "
            "Chaque scan analyse les certificats SSL, CVEs, headers HTTP et DNS "
            "en temps réel depuis des sources externes vérifiées."
        ),
        references=["streaming/scheduler.py", "core/aggregator.py"],
    ),
]

# ── Score et résumé ────────────────────────────────────────────────────────────

_STATUS_WEIGHT = {
    "IMPLEMENTED":     1.0,
    "PARTIAL":         0.5,
    "PROCEDURAL":      0.5,
    "NOT_IMPLEMENTED": 0.0,
}

_STATUS_LABEL = {
    "IMPLEMENTED":     "Mis en œuvre",
    "PARTIAL":         "Partiel",
    "PROCEDURAL":      "Procédural",
    "NOT_IMPLEMENTED": "Non mis en œuvre",
}


def compute_score(controls: list[Control] | None = None) -> dict:
    """Retourne le score de conformité et les compteurs par statut."""
    if controls is None:
        controls = CONTROLS
    total = len(controls)
    counts: dict[str, int] = {s: 0 for s in _STATUS_WEIGHT}
    weighted = 0.0
    for c in controls:
        counts[c.status] = counts.get(c.status, 0) + 1
        weighted += _STATUS_WEIGHT[c.status]
    score_pct = round(weighted / total * 100, 1) if total else 0.0
    return {
        "total": total,
        "score_pct": score_pct,
        "counts": counts,
        "assessment_date": date.today().isoformat(),
        "level": "CPCSC Niveau 1",
        "framework": "NIST SP 800-171 / FAR 52.204-21",
    }


def as_dict(controls: list[Control] | None = None) -> dict:
    """Sérialise l'évaluation complète en dict JSON-compatible."""
    if controls is None:
        controls = CONTROLS
    summary = compute_score(controls)
    domains: dict[str, list[dict]] = {}
    for c in controls:
        entry = {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "status_label": _STATUS_LABEL.get(c.status, c.status),
            "evidence": c.evidence,
            "gap": c.gap,
            "priority": c.priority,
            "references": c.references,
        }
        domains.setdefault(c.domain, []).append(entry)
    return {"summary": summary, "domains": domains}
