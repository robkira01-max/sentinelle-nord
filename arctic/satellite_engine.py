"""Satellite Engine — imagerie polaire via Copernicus Data Space Ecosystem.

Sources souveraines / ouvertes (EU) :
  Copernicus Data Space : https://dataspace.copernicus.eu/
  OData API (recherche sans auth) :
    https://catalogue.dataspace.copernicus.eu/odata/v1/Products
  WMS/WMTS (visualisation sans auth) :
    https://services.dataspace.copernicus.eu/ogc/wms

Produits pertinents Arctique :
  Sentinel-1 GRD  — SAR, pénètre les nuages, cartographie glace marine
  Sentinel-2 L2A  — optique, résolution 10m (limité par couverture nuageuse)
  Sentinel-3 OLCI — couleur océan, étendue glace, résolution 300m
"""
import logging
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger(__name__)

_ODATA   = "https://catalogue.dataspace.copernicus.eu/odata/v1/Products"
_WMS_BASE = "https://services.dataspace.copernicus.eu/ogc/wms"

# Paramètres WMS par collection — couches visualisables sans authentification
WMS_LAYERS: dict[str, dict] = {
    "SENTINEL-1": {
        "layer":      "S1_SAR_GRD_SIGMA0_ASCENDING,S1_SAR_GRD_SIGMA0_DESCENDING",
        "description":"SAR sigma0 — détection navires + glace",
        "style":      "grayscale",
    },
    "SENTINEL-2": {
        "layer":      "TRUE-COLOR",
        "description":"Couleur naturelle 10m",
        "style":      "DEFAULT",
    },
    "SENTINEL-3": {
        "layer":      "OLCI-TRUE-COLOR",
        "description":"Couleur naturelle 300m — étendue glace",
        "style":      "DEFAULT",
    },
}

# Collections et types de produits Arctique
COLLECTIONS = {
    "SENTINEL-1": {"type": "GRD",   "days_back": 3,  "priority": "HIGH"},
    "SENTINEL-2": {"type": "L2A",   "days_back": 7,  "priority": "MEDIUM"},
    "SENTINEL-3": {"type": "OL_1_EFR___", "days_back": 2, "priority": "HIGH"},
}

# Zones Arctique prédéfinies (bbox WKT)
ARCTIC_AOI: dict[str, str] = {
    "northwest_passage": "POLYGON((-141 69,-80 69,-80 75,-141 75,-141 69))",
    "beaufort_sea":      "POLYGON((-141 68,-120 68,-120 78,-141 78,-141 68))",
    "baffin_bay":        "POLYGON((-80 65,-55 65,-55 78,-80 78,-80 65))",
    "hudson_bay":        "POLYGON((-95 55,-65 55,-65 65,-95 65,-95 55))",
}


class SatelliteEngine:
    """Collecteur imagerie satellitaire Arctique — Copernicus (souverain EU)."""

    def fetch(self, bbox: dict | None = None,
              collections: list[str] | None = None,
              days_back: int = 5) -> dict:
        """Recherche les produits récents sur la zone Arctique canadienne."""
        if bbox is None:
            bbox = {"lat_min": 60, "lat_max": 90,
                    "lon_min": -141, "lon_max": -52}

        collections = collections or list(COLLECTIONS.keys())
        dt_from = (datetime.now(timezone.utc) - timedelta(days=days_back)
                   ).strftime("%Y-%m-%dT00:00:00.000Z")
        dt_to   = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.000Z")

        wkt = self._bbox_to_wkt(bbox)
        all_products: list[dict] = []
        errors: list[str] = []

        for col in collections:
            try:
                products = self._search(col, wkt, dt_from, dt_to)
                all_products.extend(products)
                log.info("Satellite %s: %d produits trouvés", col, len(products))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{col}: {exc}")

        all_products.sort(key=lambda p: p.get("date", ""), reverse=True)

        return {
            "source":    "Copernicus Data Space Ecosystem (EU)",
            "sovereign": False,
            "note":      "Données EU Copernicus — open data, licence CC-BY",
            "bbox":      bbox,
            "period":    {"from": dt_from, "to": dt_to},
            "total":     len(all_products),
            "products":  all_products,
            "wms":       self._wms_info(bbox),
            "aoi":       ARCTIC_AOI,
            "errors":    errors,
        }

    def fetch_aoi(self, aoi_name: str, days_back: int = 5) -> dict:
        """Recherche par zone Arctique prédéfinie (NWP, Beaufort, etc.)."""
        if aoi_name not in ARCTIC_AOI:
            return {"error": f"AOI inconnue. Options: {list(ARCTIC_AOI.keys())}"}
        return self._search_by_wkt(ARCTIC_AOI[aoi_name], days_back, aoi_name)

    # ── privé ───────────────────────────────────────────────────────

    def _search(self, collection: str, wkt: str,
                dt_from: str, dt_to: str) -> list[dict]:
        col_cfg = COLLECTIONS.get(collection, {})
        filter_str = (
            f"Collection/Name eq '{collection}'"
            f" and OData.CSC.Intersects(area=geography'SRID=4326;{wkt}')"
            f" and ContentDate/Start gt {dt_from}"
            f" and ContentDate/Start lt {dt_to}"
        )
        if col_cfg.get("type"):
            filter_str += f" and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq '{col_cfg['type']}')"

        r = requests.get(
            _ODATA,
            params={"$filter": filter_str, "$top": 20, "$orderby": "ContentDate/Start desc"},
            timeout=15,
            headers={"Accept": "application/json"},
        )
        r.raise_for_status()
        items = r.json().get("value", [])
        return [self._normalize(p, collection) for p in items]

    def _search_by_wkt(self, wkt: str, days_back: int,
                       aoi_name: str) -> dict:
        dt_from = (datetime.now(timezone.utc) - timedelta(days=days_back)
                   ).strftime("%Y-%m-%dT00:00:00.000Z")
        dt_to   = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.000Z")
        products: list[dict] = []
        for col in COLLECTIONS:
            try:
                products.extend(self._search(col, wkt, dt_from, dt_to))
            except Exception:  # noqa: BLE001
                pass
        return {
            "aoi":      aoi_name,
            "period":   {"from": dt_from, "to": dt_to},
            "total":    len(products),
            "products": products,
            "wms":      self._wms_info_wkt(wkt),
        }

    def _normalize(self, raw: dict, collection: str) -> dict:
        return {
            "id":         raw.get("Id"),
            "name":       raw.get("Name"),
            "collection": collection,
            "date":       raw.get("ContentDate", {}).get("Start"),
            "size_mb":    round((raw.get("ContentLength") or 0) / 1_048_576, 1),
            "footprint":  raw.get("Footprint"),
            "online":     raw.get("Online", False),
            "wms_layer":  WMS_LAYERS.get(collection, {}).get("layer"),
            "download":   (f"https://catalogue.dataspace.copernicus.eu"
                           f"/odata/v1/Products({raw.get('Id')})/$value"
                           if raw.get("Online") else None),
            "viewer":     (f"https://browser.dataspace.copernicus.eu/"
                           f"?productId={raw.get('Id')}"),
        }

    def _wms_info(self, bbox: dict) -> dict:
        bbox_str = (f"{bbox['lon_min']},{bbox['lat_min']},"
                    f"{bbox['lon_max']},{bbox['lat_max']}")
        return self._build_wms_urls(bbox_str)

    def _wms_info_wkt(self, wkt: str) -> dict:
        return {"base": _WMS_BASE, "layers": WMS_LAYERS, "wkt": wkt}

    def _build_wms_urls(self, bbox_str: str) -> dict:
        base_params = (f"SERVICE=WMS&VERSION=1.3.0&REQUEST=GetMap"
                       f"&CRS=EPSG:4326&WIDTH=1024&HEIGHT=768"
                       f"&BBOX={bbox_str}")
        return {
            "base":   _WMS_BASE,
            "layers": {
                col: (f"{_WMS_BASE}?{base_params}"
                      f"&LAYERS={cfg['layer']}&STYLES={cfg['style']}"
                      f"&FORMAT=image/png")
                for col, cfg in WMS_LAYERS.items()
            },
            "capabilities": f"{_WMS_BASE}?SERVICE=WMS&REQUEST=GetCapabilities",
        }

    @staticmethod
    def _bbox_to_wkt(bbox: dict) -> str:
        lo, la = bbox["lon_min"], bbox["lat_min"]
        hi, lb = bbox["lon_max"], bbox["lat_max"]
        return f"POLYGON(({lo} {la},{hi} {la},{hi} {lb},{lo} {lb},{lo} {la}))"
