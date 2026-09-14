"""ADS-B Engine — trafic aérien polaire.

Source principale : OpenSky Network REST API (EU, libre, sans inscription)
  https://opensky-network.org/api/states/all?lamin=&lomin=&lamax=&lomax=

Couverture polaire : limitée au-delà de 75°N (peu de stations sol).
Pour meilleure couverture : ADS-B Exchange (payant) ou récepteur local.
"""
import requests

_OPENSKY_URL = "https://opensky-network.org/api/states/all"

# Champs OpenSky (index dans la liste `states`)
_FIELDS = ["icao24", "callsign", "origin_country", "time_position",
           "last_contact", "longitude", "latitude", "baro_altitude",
           "on_ground", "velocity", "true_track", "vertical_rate",
           "sensors", "geo_altitude", "squawk", "spi", "position_source"]

# Aéroports nordiques de référence
ARCTIC_AIRPORTS = {
    "CYRB": {"name": "Resolute Bay",     "lat": 74.72, "lon": -94.97},
    "CYIO": {"name": "Pond Inlet",       "lat": 72.69, "lon": -77.97},
    "CYYH": {"name": "Taloyoak",         "lat": 69.55, "lon": -93.58},
    "CYLT": {"name": "Alert",            "lat": 82.52, "lon": -62.28},
    "CYUX": {"name": "Hall Beach",       "lat": 68.78, "lon": -81.24},
    "CYCO": {"name": "Kugluktuk",        "lat": 67.83, "lon": -115.14},
}


class ADSBEngine:
    """Collecteur ADS-B — vols actifs zones polaires canadiennes."""

    def fetch(self, bbox: dict) -> dict:
        try:
            r = requests.get(
                _OPENSKY_URL,
                params={
                    "lamin": bbox["lat_min"],
                    "lamax": bbox["lat_max"],
                    "lomin": bbox["lon_min"],
                    "lomax": bbox["lon_max"],
                },
                timeout=15,
            )
            r.raise_for_status()
            payload = r.json()
            states = payload.get("states") or []
            flights = [self._normalize(s) for s in states]
            return {
                "source":       "OpenSky Network",
                "bbox":         bbox,
                "time":         payload.get("time"),
                "count":        len(flights),
                "flights":      flights,
                "airports_ref": ARCTIC_AIRPORTS,
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "source": "OpenSky Network"}

    def _normalize(self, state: list) -> dict:
        d = dict(zip(_FIELDS, state))
        return {
            "icao24":          d.get("icao24"),
            "callsign":        (d.get("callsign") or "").strip(),
            "origin_country":  d.get("origin_country"),
            "lat":             d.get("latitude"),
            "lon":             d.get("longitude"),
            "altitude_m":      d.get("geo_altitude"),
            "velocity_ms":     d.get("velocity"),
            "heading":         d.get("true_track"),
            "on_ground":       d.get("on_ground"),
            "squawk":          d.get("squawk"),
            "last_contact":    d.get("last_contact"),
        }
