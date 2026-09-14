"""Weather Engine — météo extrême nordique.

Source souveraine CA :
  MSC DataMart — Environnement et Changement climatique Canada
  https://dd.weather.gc.ca/

Données disponibles sans inscription, licence ouverte (ECCC Open).
METAR (aviation) = format universel pour conditions actuelles.
"""
import requests

_METAR_URL = "https://dd.weather.gc.ca/observations/metar/stations/{station}.metar"
_SWOB_URL  = "https://dd.weather.gc.ca/observations/swob-ml/latest/{station}"

# Stations nordiques clés
ARCTIC_STATIONS = {
    "CYRB": {"name": "Resolute Bay",         "lat": 74.72, "lon": -94.97, "prov": "NU"},
    "CYLT": {"name": "Alert (NWS)",           "lat": 82.52, "lon": -62.28, "prov": "NU"},
    "CYIO": {"name": "Pond Inlet",            "lat": 72.69, "lon": -77.97, "prov": "NU"},
    "CYUX": {"name": "Hall Beach",            "lat": 68.78, "lon": -81.24, "prov": "NU"},
    "CYCO": {"name": "Kugluktuk",             "lat": 67.83, "lon": -115.14,"prov": "NU"},
    "CYDH": {"name": "Inuvik Mike Zubko",     "lat": 68.30, "lon": -133.49,"prov": "NT"},
    "CYFB": {"name": "Iqaluit",               "lat": 63.76, "lon": -68.56, "prov": "NU"},
    "CYAB": {"name": "Arctic Bay",            "lat": 73.00, "lon": -85.04, "prov": "NU"},
    "CWSA": {"name": "Eureka (Ellesmere Is.)", "lat": 79.99, "lon": -85.93, "prov": "NU"},
}

# Seuils alertes conditions extrêmes
EXTREME_THRESHOLDS = {
    "wind_kt":    35,   # tempête
    "visibility": 400,  # white-out (mètres)
    "temp_c":    -40,   # froid extrême
}


class WeatherEngine:
    """Collecteur météo nordique — MSC DataMart (souverain CA)."""

    def fetch(self, station: str = "CYRB") -> dict:
        station = station.upper()
        if station not in ARCTIC_STATIONS:
            return {
                "error":    f"Station inconnue: {station}",
                "stations": list(ARCTIC_STATIONS.keys()),
            }

        info = ARCTIC_STATIONS[station]
        result = {
            "source":   "MSC DataMart — ECCC",
            "sovereign": True,
            "station":  station,
            "name":     info["name"],
            "lat":      info["lat"],
            "lon":      info["lon"],
            "province": info["prov"],
        }

        # METAR brut
        try:
            r = requests.get(
                _METAR_URL.format(station=station),
                timeout=8,
            )
            if r.status_code == 200:
                lines = [l.strip() for l in r.text.strip().splitlines() if l.strip()]
                result["metar_raw"] = lines[-1] if lines else None
                result["metar_feed"] = _METAR_URL.format(station=station)
            else:
                result["metar_raw"] = None
        except Exception as exc:  # noqa: BLE001
            result["metar_error"] = str(exc)

        # Toutes les stations pour vue d'ensemble
        result["all_stations"] = ARCTIC_STATIONS
        result["extreme_thresholds"] = EXTREME_THRESHOLDS
        result["datamart_base"] = "https://dd.weather.gc.ca/observations/metar/stations/"
        return result

    def fetch_all(self) -> list[dict]:
        """Snapshot météo de toutes les stations nordiques connues."""
        return [self.fetch(s) for s in ARCTIC_STATIONS]
