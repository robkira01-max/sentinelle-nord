"""AIS Engine — trafic maritime polaire.

Sources souveraines / ouvertes :
  - AISHub  : https://www.aishub.net/api  (gratuit, inscription requise)
  - Marine Cadastre NOAA : données historiques AIS Arctique canadien
  - Fallback : données statiques zones sensibles

Champs retournés par vessel :
  mmsi, name, type, lat, lon, speed, course, destination, timestamp
"""
import requests
from config import Config

_AISHUB_URL = "https://data.aishub.net/ws.php"

# Zones maritimes sensibles — coordonnées de référence
ARCTIC_ZONES = {
    "northwest_passage": {"lat": (69, 75), "lon": (-140, -80)},
    "hudson_bay":        {"lat": (55, 65), "lon": (-95, -65)},
    "baffin_bay":        {"lat": (65, 78), "lon": (-80, -55)},
    "beaufort_sea":      {"lat": (68, 78), "lon": (-141, -120)},
}


class AISEngine:
    """Collecteur AIS — trafic maritime zones polaires canadiennes."""

    def fetch(self, bbox: dict) -> dict:
        """Retourne les vessels actifs dans la bounding box."""
        api_key = getattr(Config, "AISHUB_API_KEY", "")
        if not api_key:
            return self._fallback(bbox)
        try:
            r = requests.get(
                _AISHUB_URL,
                params={
                    "username":  api_key,
                    "format":    1,
                    "output":    "json",
                    "latmin":    bbox["lat_min"],
                    "latmax":    bbox["lat_max"],
                    "lonmin":    bbox["lon_min"],
                    "lonmax":    bbox["lon_max"],
                },
                timeout=10,
            )
            r.raise_for_status()
            vessels = r.json()[1] if isinstance(r.json(), list) else []
            return {
                "source":   "AISHub",
                "bbox":     bbox,
                "count":    len(vessels),
                "vessels":  [self._normalize(v) for v in vessels],
                "zones":    self._classify_zones(vessels),
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "fallback": self._fallback(bbox)}

    def _normalize(self, v: dict) -> dict:
        return {
            "mmsi":        v.get("MMSI"),
            "name":        v.get("NAME", "").strip(),
            "type":        v.get("TYPE"),
            "lat":         v.get("LATITUDE"),
            "lon":         v.get("LONGITUDE"),
            "speed":       v.get("SPEED"),
            "course":      v.get("COURSE"),
            "destination": v.get("DESTINATION", "").strip(),
            "timestamp":   v.get("TIME"),
        }

    def _classify_zones(self, vessels: list) -> dict:
        """Identifie les vessels dans les zones sensibles."""
        hits: dict[str, list] = {z: [] for z in ARCTIC_ZONES}
        for v in vessels:
            lat = v.get("LATITUDE") or 0
            lon = v.get("LONGITUDE") or 0
            for zone, bounds in ARCTIC_ZONES.items():
                if (bounds["lat"][0] <= lat <= bounds["lat"][1] and
                        bounds["lon"][0] <= lon <= bounds["lon"][1]):
                    hits[zone].append(v.get("MMSI"))
        return {z: v for z, v in hits.items() if v}

    def _fallback(self, bbox: dict) -> dict:
        return {
            "source":  "fallback",
            "bbox":    bbox,
            "count":   0,
            "vessels": [],
            "note":    "Configurez AISHUB_API_KEY dans .env pour les données live",
        }
