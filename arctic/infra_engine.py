"""Infrastructure Engine — infrastructures critiques nordiques.

Données ouvertes :
  - NRCan Open Data : https://open.canada.ca/data/fr/dataset
  - StatsCan : communautés nordiques
  - Données de connaissance terrain (bases militaires connues publiquement)

Catégories surveillées :
  télécommunications, énergie, transport, eau, santé, défense (public)
"""
import requests

_NRCAN_API = "https://geogratis.gc.ca/api/en/nrcan-rncan/ess-sst"

# Infrastructures critiques nordiques — données publiques consolidées
ARCTIC_INFRASTRUCTURE: dict[str, list[dict]] = {
    "telecommunications": [
        {"name": "Telesat Anik F3",      "type": "satellite", "operator": "Telesat CA",
         "coverage": "Arctique canadien complet", "sovereign": True},
        {"name": "Viasat ViaSat-2",      "type": "satellite", "operator": "Viasat US",
         "coverage": "Nord Canada partiel", "sovereign": False},
        {"name": "Nunaliit/CRTC",        "type": "terrestrial broadband",
         "operator": "SSi Micro CA", "coverage": "Nunavut communautés", "sovereign": True},
        {"name": "Undersea cable Iqaluit", "type": "fibre", "operator": "Sakku CA",
         "status": "planned 2025", "sovereign": True},
    ],
    "energy": [
        {"name": "Iqaluit Power Corp",   "type": "diesel", "region": "Nunavut",
         "operator": "QEC", "vulnerable": True},
        {"name": "Inuvik Natural Gas",   "type": "gas pipeline",
         "region": "NWT", "operator": "GNWT"},
        {"name": "Diavik Wind Farm",     "type": "wind", "region": "NWT",
         "capacity_mw": 9.2, "operator": "Rio Tinto"},
    ],
    "transport": [
        {"name": "Aéroport Iqaluit CYFB",   "type": "airport", "icao": "CYFB",
         "runway_m": 2590, "military_joint": True},
        {"name": "Aéroport Resolute CYRB",   "type": "airport", "icao": "CYRB",
         "military_joint": True, "nato_relevance": "high"},
        {"name": "Port Nanisivik",           "type": "deepwater port", "status": "naval",
         "operator": "RCN", "strategic": True, "note": "Seul port en eau profonde Arctique CA"},
        {"name": "Port Churchill",           "type": "commercial port",
         "region": "Hudson Bay", "rail_connected": True},
    ],
    "military_public": [
        {"name": "CFS Alert",            "type": "signals intelligence",
         "lat": 82.52, "lon": -62.28, "operator": "CAF",
         "note": "Station la plus septentrionale du monde — SIGINT"},
        {"name": "CFS Leitrim",          "type": "SIGINT support", "region": "Ottawa"},
        {"name": "NORAD North Bay",      "type": "command", "region": "Ontario"},
        {"name": "4 Wing Cold Lake",     "type": "fighter base", "icao": "CYOD",
         "aircraft": "CF-18", "arctic_response": True},
        {"name": "Nanisivik Naval Facility", "type": "naval", "lat": 73.07, "lon": -84.57,
         "operator": "RCN", "status": "operational 2023"},
    ],
    "health": [
        {"name": "Hôpital Qikiqtani",    "region": "Iqaluit", "beds": 32,
         "operator": "GN", "air_medevac_only": True},
        {"name": "Centre Stanton",       "region": "Yellowknife", "beds": 170},
    ],
    "water": [
        {"name": "Iqaluit water treatment", "type": "municipal",
         "source": "Lake Geraldine", "vulnerable": True,
         "note": "Déversement 2021 — résilience faible"},
    ],
}

REGIONS = ["nunavut", "nwt", "yukon", "nunavik", "all"]


class InfraEngine:
    """Collecteur infrastructures critiques nordiques."""

    def fetch(self, region: str = "all") -> dict:
        region = region.lower()
        if region not in REGIONS:
            return {"error": f"Région inconnue. Options: {REGIONS}"}

        data = ARCTIC_INFRASTRUCTURE.copy()
        if region != "all":
            data = {
                cat: [i for i in items
                      if region in str(i).lower()]
                for cat, items in data.items()
            }

        total = sum(len(v) for v in data.values())
        vulnerables = [
            item for items in data.values()
            for item in items if item.get("vulnerable")
        ]

        return {
            "source":      "NRCan + données publiques consolidées",
            "sovereign":   True,
            "region":      region,
            "total_items": total,
            "vulnerable":  vulnerables,
            "categories":  data,
            "nrcan_api":   _NRCAN_API,
        }
