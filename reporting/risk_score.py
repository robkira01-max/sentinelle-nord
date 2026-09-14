"""Calcul du score de risque pondéré CVSS × KEV × âge × contexte.

Formule inspirée CISA KEV weighting + PTES severity matrix :
  score_final = Σ(CVSS_i × kev_mult × age_mult × context_mult) / n_findings
  puis normalisé sur 0–10.

Paramètres :
  - CVSS base score (NVD)
  - KEV multiplier : ×1.5 si dans CISA KEV
  - Age multiplier : ×1.2 si patch disponible depuis > 180j
  - Contexte :
      email_exposure    : ×1.1 (DMARC absent, SPF softfail)
      internet_exposed  : ×1.2 (service admin sur port public)
      no_auth           : ×1.3 (interface sans auth détectée)
      eol_software      : ×1.1 (version EOL)
      domain_expiry     : ×1.0 (expiration domaine < 30j = finding critique fixe)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── Constantes de pondération ─────────────────────────────────────────────────

_KEV_MULT       = 1.5   # Vulnérabilité exploitée in-the-wild (CISA KEV)
_AGE_STALE_MULT = 1.2   # Patch dispo > 180j non appliqué
_CTX_EMAIL      = 1.1   # Exposition email (DMARC/SPF/DKIM)
_CTX_EXPOSED    = 1.2   # Service admin/infra exposé publiquement
_CTX_NO_AUTH    = 1.3   # Interface sans authentification
_CTX_EOL        = 1.1   # Logiciel EOL / version non maintenue
_DOMAIN_EXPIRY_DAYS = 30  # Seuil critique expiration domaine

# Labels CVSS → sévérité affichée
_CVSS_LABELS = {
    (9.0, 10.0): ("CRITIQUE",  "#dc3545"),
    (7.0,  8.9): ("ÉLEVÉ",     "#fd7e14"),
    (4.0,  6.9): ("MOYEN",     "#ffc107"),
    (0.1,  3.9): ("FAIBLE",    "#28a745"),
    (0.0,  0.0): ("INFO",      "#6c757d"),
}


def _cvss_label(score: float) -> tuple[str, str]:
    for (lo, hi), label in _CVSS_LABELS.items():
        if lo <= score <= hi:
            return label
    return ("INFO", "#6c757d")


@dataclass
class Finding:
    title:          str
    cvss:           float = 0.0
    kev:            bool  = False    # dans CISA KEV ?
    patch_days:     int   = 0        # jours depuis patch dispo (0 = inconnu)
    email_exposure: bool  = False
    internet_exposed: bool = False
    no_auth:        bool  = False
    eol:            bool  = False
    notes:          str   = ""

    @property
    def weighted_score(self) -> float:
        s = self.cvss
        if self.kev:
            s *= _KEV_MULT
        if self.patch_days > 180:
            s *= _AGE_STALE_MULT
        if self.email_exposure:
            s *= _CTX_EMAIL
        if self.internet_exposed:
            s *= _CTX_EXPOSED
        if self.no_auth:
            s *= _CTX_NO_AUTH
        if self.eol:
            s *= _CTX_EOL
        return round(min(s, 10.0), 2)

    @property
    def severity(self) -> tuple[str, str]:
        return _cvss_label(self.weighted_score)


def _extract_findings_from_report(report: dict) -> list[Finding]:
    """Transforme un rapport de scan JSON en liste de Findings pondérables."""
    findings: list[Finding] = []
    sections = report.get("sections", {})

    # ── Email security ─────────────────────────────────────────
    http_sections = sections.get("http", [])
    for sec in http_sections:
        data = sec.get("data", {})
        dmarc = data.get("dmarc", "")
        spf   = data.get("spf", "")
        ssl   = data.get("ssl", {})

        if not dmarc:
            findings.append(Finding(
                title="DMARC absent — spoofing email possible",
                cvss=6.5, email_exposure=True,
                notes="Aucun enregistrement DMARC détecté"
            ))
        elif "p=none" in (dmarc or ""):
            findings.append(Finding(
                title="DMARC p=none — politique non enforced",
                cvss=5.3, email_exposure=True,
                notes=f"DMARC: {dmarc[:60]}"
            ))
        elif "p=quarantine" in (dmarc or ""):
            findings.append(Finding(
                title="DMARC p=quarantine — politique partielle",
                cvss=3.1, email_exposure=True,
                notes=f"DMARC: {dmarc[:60]}"
            ))

        if spf and "~all" in spf:
            findings.append(Finding(
                title="SPF softfail (~all) — envoi non rejeté",
                cvss=4.3, email_exposure=True,
                notes=f"SPF: {spf[:60]}"
            ))
        elif not spf:
            findings.append(Finding(
                title="SPF absent",
                cvss=4.0, email_exposure=True
            ))

        # SSL expiry
        days_left = (ssl or {}).get("days_left")
        if isinstance(days_left, int):
            if days_left < 0:
                findings.append(Finding(
                    title=f"Certificat SSL expiré ({abs(days_left)}j)",
                    cvss=7.5, internet_exposed=True, patch_days=abs(days_left),
                    notes="TLS interception possible"
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title=f"Certificat SSL expire dans {days_left}j",
                    cvss=4.0, internet_exposed=True
                ))

        # Headers manquants
        for h in (data.get("missing_headers") or []):
            findings.append(Finding(
                title=f"Header sécurité absent : {h}",
                cvss=3.1, internet_exposed=True,
                notes="CSP / HSTS / X-Frame absent"
            ))

    # ── WHOIS — expiration domaine ─────────────────────────────
    for sec in sections.get("whois", []):
        data = sec.get("data", {})
        exp = data.get("expiration_date")
        if exp:
            exp_str = str(exp)[:10]
            try:
                exp_dt = datetime.fromisoformat(exp_str).replace(tzinfo=timezone.utc)
                days_to_exp = (exp_dt - datetime.now(timezone.utc)).days
                if days_to_exp < _DOMAIN_EXPIRY_DAYS:
                    findings.append(Finding(
                        title=f"Expiration domaine dans {days_to_exp}j",
                        cvss=8.5, internet_exposed=True,
                        notes=f"Expire le {exp_str} — squatting possible"
                    ))
            except (ValueError, TypeError):
                pass

    # ── CVEs ───────────────────────────────────────────────────
    for sec in sections.get("vulns", []):
        for item in (sec.get("data", {}) or {}).get("items", []):
            cvss = float(item.get("score") or 0)
            if cvss > 0:
                findings.append(Finding(
                    title=f"{item.get('cve','CVE-?')} — {item.get('description','')[:60]}",
                    cvss=cvss,
                    internet_exposed=True,
                    notes=item.get("severity", "")
                ))

    return findings


def compute_risk_score(report: dict) -> dict:
    """Calcule le score de risque pondéré d'un scan complet.

    Retourne :
      {
        "score": 6.7,              # 0–10
        "grade": "C",              # A–F
        "label": "MOYEN",
        "color": "#ffc107",
        "findings": [...],         # liste détaillée
        "breakdown": {...},        # par catégorie
        "critical_count": 2,
        "methodology": "..."
      }
    """
    findings = _extract_findings_from_report(report)

    if not findings:
        return {
            "score": 10.0, "grade": "A+", "label": "EXCELLENT",
            "color": "#28a745", "findings": [], "breakdown": {},
            "critical_count": 0,
            "methodology": "CVSS × KEV × Age × Context"
        }

    # Score agrégé : max weighted (le pire finding domine, penalisé par nb total)
    weighted_scores = [f.weighted_score for f in findings]
    max_score  = max(weighted_scores)
    mean_score = sum(weighted_scores) / len(weighted_scores)
    # Formule hybride : 60% max, 40% moyenne (pénalise l'accumulation)
    raw = min(0.6 * max_score + 0.4 * mean_score, 10.0)
    final = round(raw, 1)

    # Inversion pour affichage (10 = risque MAXIMAL; grade = risque)
    grade = _risk_grade(final)
    label, color = _cvss_label(final)

    breakdown: dict[str, list[dict]] = {}
    for f in sorted(findings, key=lambda x: x.weighted_score, reverse=True):
        cat = _categorize(f.title)
        breakdown.setdefault(cat, []).append({
            "title":       f.title,
            "cvss_base":   f.cvss,
            "weighted":    f.weighted_score,
            "severity":    f.severity[0],
            "color":       f.severity[1],
            "kev":         f.kev,
            "notes":       f.notes,
            "multipliers": _explain_multipliers(f),
        })

    critical_count = sum(1 for f in findings if f.weighted_score >= 9.0)

    return {
        "score":          final,
        "grade":          grade,
        "label":          label,
        "color":          color,
        "findings":       [{"title": f.title, "weighted": f.weighted_score,
                            "severity": f.severity[0], "color": f.severity[1]}
                           for f in sorted(findings,
                                           key=lambda x: x.weighted_score,
                                           reverse=True)],
        "breakdown":      breakdown,
        "critical_count": critical_count,
        "total_findings": len(findings),
        "methodology":    "Score = 0.6×max(CVSS_weighted) + 0.4×mean(CVSS_weighted) "
                          "| Multiplicateurs: KEV×1.5, Age>180j×1.2, "
                          "Email×1.1, Exposé×1.2, NoAuth×1.3, EOL×1.1",
    }


def _risk_grade(score: float) -> str:
    if score >= 9.0: return "F"
    if score >= 7.0: return "D"
    if score >= 5.0: return "C"
    if score >= 3.0: return "B"
    if score >= 1.0: return "A"
    return "A+"


def _categorize(title: str) -> str:
    t = title.lower()
    if any(w in t for w in ("dmarc", "spf", "dkim", "email")): return "Email Security"
    if any(w in t for w in ("ssl", "tls", "certificat")): return "TLS/SSL"
    if any(w in t for w in ("cve-", "vuln", "patch")): return "CVE / Vulnérabilités"
    if any(w in t for w in ("domaine", "domain", "expir")): return "Domaine"
    if any(w in t for w in ("header", "csp", "hsts")): return "HTTP Headers"
    if any(w in t for w in ("auth", "login", "admin")): return "Authentification"
    return "Autre"


def _explain_multipliers(f: Finding) -> list[str]:
    parts = [f"CVSS base: {f.cvss}"]
    if f.kev:            parts.append("×1.5 KEV (exploité in-the-wild)")
    if f.patch_days > 180: parts.append(f"×1.2 patch dispo {f.patch_days}j sans MAJ")
    if f.email_exposure: parts.append("×1.1 exposition email")
    if f.internet_exposed: parts.append("×1.2 exposé internet")
    if f.no_auth:        parts.append("×1.3 sans authentification")
    if f.eol:            parts.append("×1.1 EOL")
    parts.append(f"→ pondéré: {f.weighted_score}")
    return parts
