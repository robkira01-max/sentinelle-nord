"""Corrélation d'actifs par organisation.

Groupe les cibles scannées selon les signaux communs :
  ASN       — même numéro de système autonome (URLScan / Shodan)
  WHOIS_ORG — même organisation registraire (WHOIS)
  NAMESERVER— même serveur de noms (WHOIS)
  SSL_SAN   — chevauchement de Subject Alternative Names (HTTP collector)
  IP        — même adresse IP (URLScan / Shodan)

Algorithme : union-find (path compression + union by rank).
Toutes les fonctions sont pures (pas d'I/O DB).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── Structures ────────────────────────────────────────────────────────────────


@dataclass
class AssetFeatures:
    target: str
    asn: str | None = None       # "AS15169"
    ip: str | None = None
    whois_org: str | None = None  # normalisé lowercase
    nameservers: list[str] = field(default_factory=list)   # lowercase, sans dot final
    ssl_sans: list[str] = field(default_factory=list)       # domaines normalisés
    registrar: str | None = None


@dataclass
class CorrelationSignal:
    signal_type: str   # ASN | WHOIS_ORG | NAMESERVER | SSL_SAN | IP
    value: str
    targets: list[str]


@dataclass
class OrgCluster:
    cluster_id: str
    targets: list[str]
    signals: list[CorrelationSignal]
    inferred_org: str  # valeur de signal la plus discriminante


# ── Normalisation ─────────────────────────────────────────────────────────────

_AS_RE = re.compile(r"\b(AS\d+)\b", re.IGNORECASE)


def _norm_asn(raw: str | None) -> str | None:
    """Extrait 'AS12345' d'une chaîne comme 'AS12345 Google LLC'."""
    if not raw:
        return None
    m = _AS_RE.search(raw)
    return m.group(1).upper() if m else raw.upper().strip()


def _norm_org(raw: str | None) -> str | None:
    if not raw:
        return None
    return raw.strip().lower()


def _norm_ns(ns: list[str] | str | None) -> list[str]:
    if not ns:
        return []
    if isinstance(ns, str):
        ns = [ns]
    out = []
    for n in ns:
        n = str(n).strip().lower().rstrip(".")
        if n:
            out.append(n)
    return out


def _norm_domain(d: str | None) -> str:
    if not d:
        return ""
    return d.strip().lower().lstrip("*.").rstrip(".")


# ── Extraction de features ────────────────────────────────────────────────────


def extract_features(target: str, results: list[dict[str, Any]]) -> AssetFeatures:
    """Construit AssetFeatures depuis une liste de Result.data + source.

    Chaque élément attendu : {"source": str, "data": dict}.
    """
    feat = AssetFeatures(target=target)
    for r in results:
        source = r.get("source", "")
        data = r.get("data") or {}
        if not isinstance(data, dict):
            continue

        if source == "urlscan":
            feat.asn = feat.asn or _norm_asn(data.get("asn"))
            feat.ip  = feat.ip  or data.get("ip")

        elif source == "whois":
            feat.whois_org   = _norm_org(data.get("org"))
            feat.registrar   = data.get("registrar")
            ns_raw = data.get("name_servers")
            feat.nameservers = _norm_ns(ns_raw)

        elif source == "http":
            ssl = data.get("ssl") or {}
            sans = ssl.get("sans") or []
            feat.ssl_sans = [_norm_domain(s) for s in sans if _norm_domain(s)]

        elif source == "shodan":
            feat.asn = feat.asn or _norm_asn(data.get("org"))
            feat.ip  = feat.ip  or data.get("ip")

    return feat


# ── Union-Find ────────────────────────────────────────────────────────────────


def _make_uf(keys: list[str]) -> tuple[dict, dict]:
    parent = {k: k for k in keys}
    rank   = {k: 0 for k in keys}
    return parent, rank


def _find(parent: dict, x: str) -> str:
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def _union(parent: dict, rank: dict, x: str, y: str) -> None:
    rx, ry = _find(parent, x), _find(parent, y)
    if rx == ry:
        return
    if rank[rx] < rank[ry]:
        rx, ry = ry, rx
    parent[ry] = rx
    if rank[rx] == rank[ry]:
        rank[rx] += 1


# ── Corrélation principale ────────────────────────────────────────────────────


def correlate(features: list[AssetFeatures]) -> list[OrgCluster]:
    """Regroupe les AssetFeatures en clusters par signaux communs.

    Retourne une liste de OrgCluster triée par taille décroissante.
    Les cibles sans aucun signal partagé forment des clusters solitaires.
    """
    if not features:
        return []

    targets = [f.target for f in features]
    parent, rank = _make_uf(targets)

    # Structures inverses : valeur → liste de targets
    asn_map:  dict[str, list[str]] = {}
    org_map:  dict[str, list[str]] = {}
    ns_map:   dict[str, list[str]] = {}
    ip_map:   dict[str, list[str]] = {}
    san_map:  dict[str, list[str]] = {}

    for f in features:
        t = f.target
        if f.asn:
            asn_map.setdefault(f.asn, []).append(t)
        if f.whois_org and len(f.whois_org) >= 3:
            org_map.setdefault(f.whois_org, []).append(t)
        for ns in f.nameservers:
            ns_map.setdefault(ns, []).append(t)
        if f.ip:
            ip_map.setdefault(f.ip, []).append(t)
        for san in f.ssl_sans:
            san_map.setdefault(san, []).append(t)

    # Enregistrement des signaux (avant union pour les collecter par cluster)
    raw_signals: list[tuple[str, str, list[str]]] = []

    def _process_map(m: dict[str, list[str]], sig_type: str) -> None:
        for value, tgts in m.items():
            if len(tgts) < 2:
                continue
            raw_signals.append((sig_type, value, list(tgts)))
            for i in range(1, len(tgts)):
                _union(parent, rank, tgts[0], tgts[i])

    _process_map(asn_map,  "ASN")
    _process_map(org_map,  "WHOIS_ORG")
    _process_map(ns_map,   "NAMESERVER")
    _process_map(ip_map,   "IP")
    _process_map(san_map,  "SSL_SAN")

    # Regrouper par racine union-find
    groups: dict[str, list[str]] = {}
    for t in targets:
        root = _find(parent, t)
        groups.setdefault(root, []).append(t)

    # Construire les clusters
    clusters: list[OrgCluster] = []
    for idx, (root, members) in enumerate(
            sorted(groups.items(), key=lambda kv: -len(kv[1])), start=1):
        member_set = set(members)
        sigs: list[CorrelationSignal] = []
        for sig_type, value, sig_targets in raw_signals:
            overlap = [t for t in sig_targets if t in member_set]
            if len(overlap) >= 2:
                sigs.append(CorrelationSignal(
                    signal_type=sig_type,
                    value=value,
                    targets=overlap,
                ))

        # Org inférée : ASN > WHOIS_ORG > NAMESERVER > IP
        _prio = {"ASN": 0, "WHOIS_ORG": 1, "NAMESERVER": 2, "IP": 3, "SSL_SAN": 4}
        best = min(sigs, key=lambda s: _prio.get(s.signal_type, 9), default=None)
        inferred = best.value if best else members[0]

        clusters.append(OrgCluster(
            cluster_id=f"cluster-{idx}",
            targets=sorted(members),
            signals=sigs,
            inferred_org=inferred,
        ))

    return clusters


# ── Sérialisation ─────────────────────────────────────────────────────────────


def clusters_to_dict(clusters: list[OrgCluster]) -> dict:
    total_targets = sum(len(c.targets) for c in clusters)
    linked = sum(len(c.targets) for c in clusters if len(c.targets) > 1)
    return {
        "total_clusters": len(clusters),
        "total_targets":  total_targets,
        "linked_targets": linked,
        "clusters": [
            {
                "id":           c.cluster_id,
                "inferred_org": c.inferred_org,
                "targets":      c.targets,
                "size":         len(c.targets),
                "signals": [
                    {"type": s.signal_type, "value": s.value, "targets": s.targets}
                    for s in c.signals
                ],
            }
            for c in clusters
        ],
    }
