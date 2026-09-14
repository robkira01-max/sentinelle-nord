"""Ice Engine — données glace marine (Canadian Ice Service / ECCC).

Source souveraine CA :
  Canadian Ice Service — Environment and Climate Change Canada
  WMS/WFS : https://ice-glaces.ec.gc.ca/

Produits disponibles :
  - Eastern Arctic    : https://ice-glaces.ec.gc.ca/www_archive/IceGraph/...
  - Western Arctic    : Passage du Nord-Ouest
  - Hudson Bay        : Baie d'Hudson
  - Gulf of St. Lawrence

API REST ouverte (GeoJSON/KML) :
  https://dd.weather.gc.ca/ice_glaces/
"""
import requests

_CIS_FEED = "https://dd.weather.gc.ca/ice_glaces/charts/arctic/"

# Codes de concentration de glace (WMO egg code)
ICE_CONCENTRATION = {
    "0": "ice-free",
    "1": "< 1/10",
    "2": "1/10",
    "3": "2/10 – 3/10",
    "4": "4/10",
    "5": "5/10",
    "6": "6/10",
    "7": "7/10 – 8/10",
    "8": "9/10",
    "9": "9/10 – 10/10",
    "10": "10/10 (consolidated)",
}


_PRODUCTS = {
    "eastern_arctic": {
        "region": "Eastern Arctic (Baffin Bay, Davis Strait)",
        "url": "https://ice-glaces.ec.gc.ca/www_archive/IceGraph/page1.xhtml",
        "wms": "https://geo.weather.gc.ca/geomet?service=WMS&request=GetCapabilities",
    },
    "western_arctic": {
        "region": "Western Arctic (Beaufort Sea, NW Passage)",
        "url": "https://ice-glaces.ec.gc.ca/www_archive/IceGraph/page2.xhtml",
    },
    "hudson_bay": {
        "region": "Hudson Bay / James Bay",
        "url": "https://ice-glaces.ec.gc.ca/www_archive/IceGraph/page3.xhtml",
    },
    "gulf_st_lawrence": {
        "region": "Gulf of St. Lawrence / Great Lakes",
        "url": "https://ice-glaces.ec.gc.ca/www_archive/IceGraph/page4.xhtml",
    },
}

# URL DataMart réelle — le répertoire racine a changé en 2024
_DATAMART_URLS = [
    "https://dd.weather.gc.ca/ice_glaces/charts/arctic/",
    "https://hpfx.collab.science.gc.ca/ice_glaces/",
    "https://ice-glaces.ec.gc.ca/",
]


class IceEngine:
    """Collecteur glace marine — Canadian Ice Service (ECCC)."""

    def fetch(self) -> dict:
        """Retourne les métadonnées CIS — produits toujours disponibles,
        statut live optionnel."""
        result = {
            "source":        "Canadian Ice Service (ECCC)",
            "sovereign":     True,
            "feed_url":      _CIS_FEED,
            "concentration": ICE_CONCENTRATION,
            "products":      _PRODUCTS,          # toujours retourné
            "datamart":      _DATAMART_URLS[0],
            "datamart_alt":  _DATAMART_URLS[1:],
            "note": "Données CIS mises à jour quotidiennement. "
                    "Intégration WFS complète via GDAL/OGR recommandée.",
            "live_status":   "unknown",
        }

        # Ping optionnel — échec silencieux, ne bloque pas les métadonnées
        for url in _DATAMART_URLS:
            try:
                r = requests.get(url, timeout=6)
                result["live_status"] = "ok" if r.ok else f"http_{r.status_code}"
                result["datamart"] = url
                break
            except Exception as exc:  # noqa: BLE001
                result["live_status"] = str(exc)[:60]

        return result
