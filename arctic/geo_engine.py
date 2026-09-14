"""Geo Engine — zones sensibles Arctique + carte Folium interactive.

Données souveraines :
  - NRCan GeoGratis : limites administratives nordiques
  - Frontières maritimes (UNCLOS — revendications CA)
  - Zones EEZ (200 nm), plateau continental étendu

Folium : génère une carte HTML interactive sans dépendance cloud.
"""
from __future__ import annotations
import requests

try:
    import folium
    from folium.plugins import MarkerCluster
    _FOLIUM_OK = True
except ImportError:
    _FOLIUM_OK = False

# Zones sensibles — coordonnées publiques
SENSITIVE_ZONES: list[dict] = [
    {"name": "Passage du Nord-Ouest",  "type": "strategic_waterway",
     "center": [74.0, -100.0], "radius_km": 800,
     "note": "Contesté: CA revendique eaux intérieures, US eaux internationales"},
    {"name": "Mer de Beaufort",        "type": "resource_zone",
     "center": [72.0, -135.0], "radius_km": 500,
     "note": "Revendications chevauchantes CA/USA — hydrocarbures"},
    {"name": "Détroit de Davis",       "type": "choke_point",
     "center": [68.0, -62.0],  "radius_km": 300},
    {"name": "Baie de Baffin",         "type": "patrol_area",
     "center": [73.0, -70.0],  "radius_km": 600},
    {"name": "Baie d'Hudson",          "type": "internal_waters",
     "center": [62.0, -86.0],  "radius_km": 700},
    {"name": "Île d'Ellesmere (nord)", "type": "sovereign_territory",
     "center": [82.0, -74.0],  "radius_km": 200,
     "note": "Hans Island — résolu 2022 CA/DK"},
]

# Points d'intérêt géostratégiques
POI: list[dict] = [
    {"name": "CFS Alert",             "lat": 82.52, "lon": -62.28,
     "type": "military", "icon": "star", "color": "red"},
    {"name": "Nanisivik Naval",       "lat": 73.07, "lon": -84.57,
     "type": "naval",    "icon": "anchor", "color": "blue"},
    {"name": "Iqaluit (capitale NU)", "lat": 63.76, "lon": -68.56,
     "type": "admin",    "icon": "home", "color": "green"},
    {"name": "Resolute Bay",          "lat": 74.72, "lon": -94.97,
     "type": "airport",  "icon": "plane", "color": "blue"},
    {"name": "Alert Airport CYLT",    "lat": 82.52, "lon": -62.28,
     "type": "airport",  "icon": "plane", "color": "orange"},
    {"name": "Eureka Station",        "lat": 79.99, "lon": -85.93,
     "type": "weather",  "icon": "cloud", "color": "lightblue"},
    {"name": "Port Nanisivik",        "lat": 73.07, "lon": -84.57,
     "type": "port",     "icon": "ship",  "color": "darkblue"},
]


class GeoEngine:
    """Collecteur géospatial Arctique + rendu carte Folium."""

    def fetch(self) -> dict:
        return {
            "source":         "NRCan GeoGratis + données publiques",
            "sovereign":      True,
            "sensitive_zones": SENSITIVE_ZONES,
            "poi":            POI,
            "eez_ca_km2":     7_100_000,
            "arctic_area_km2": 1_900_000,
            "nrcan_api":      "https://geogratis.gc.ca/api/en/nrcan-rncan/ess-sst",
            "map_endpoint":   "/north/map",
        }

    def render_map(self) -> str:
        """Génère une carte HTML Folium des zones Arctique."""
        if not _FOLIUM_OK:
            return "<h2>Installez folium : pip install folium</h2>"

        m = folium.Map(
            location=[75, -90],
            zoom_start=4,
            tiles="CartoDB dark_matter",
        )

        # Zones sensibles (cercles)
        for zone in SENSITIVE_ZONES:
            folium.Circle(
                location=zone["center"],
                radius=zone["radius_km"] * 1000,
                color="#ff6b35",
                fill=True,
                fill_opacity=0.08,
                tooltip=f"<b>{zone['name']}</b><br>{zone.get('note', zone['type'])}",
            ).add_to(m)

        # POI (marqueurs)
        cluster = MarkerCluster(name="Points d'intérêt").add_to(m)
        colors = {"military": "red", "naval": "darkblue",
                  "admin": "green", "airport": "blue",
                  "weather": "lightblue", "port": "purple"}
        for poi in POI:
            folium.Marker(
                location=[poi["lat"], poi["lon"]],
                tooltip=f"<b>{poi['name']}</b><br>Type: {poi['type']}",
                icon=folium.Icon(
                    color=colors.get(poi["type"], "gray"),
                    icon="info-sign",
                ),
            ).add_to(cluster)

        folium.LayerControl().add_to(m)
        return m._repr_html_()
