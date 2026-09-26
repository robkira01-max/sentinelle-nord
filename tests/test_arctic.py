"""Tests — endpoints pipeline Arctique."""
from unittest.mock import patch, MagicMock

import pytest


_BBOX_PARAMS = "?lat_min=60&lat_max=80&lon_min=-100&lon_max=-60"

_AIS_DATA = {"source": "ais_mock", "count": 3,
             "vessels": [{"mmsi": "123456789", "lat": 70.0, "lon": -90.0}]}
_ADSB_DATA = {"source": "adsb_mock", "count": 2,
              "flights": [{"icao": "C3ABC", "lat": 65.0, "lon": -95.0}]}
_ICE_DATA = {"source": "ice_mock", "coverage": []}
_WEATHER_DATA = {"station": "CYRB", "temp_c": -15, "wind_kmh": 30}
_INFRA_DATA = {"region": "nunavut", "facilities": []}
_GEO_DATA = {"type": "FeatureCollection", "features": []}
_SAT_DATA = {"source": "sat_mock", "scenes": []}


# ── Accès non authentifié ─────────────────────────────────────────────────────

class TestArcticAuthRequired:
    @pytest.mark.parametrize("endpoint", [
        "/north/ais", "/north/adsb", "/north/ice",
        "/north/weather", "/north/infrastructure",
        "/north/geo", "/north/satellite",
    ])
    def test_requires_auth(self, client, endpoint):
        r = client.get(endpoint)
        assert r.status_code == 401


# ── AIS ───────────────────────────────────────────────────────────────────────

class TestAIS:
    @patch("arctic.ais_engine.AISEngine")
    def test_ais_ok(self, MockAIS, analyst_client):
        MockAIS.return_value.fetch.return_value = _AIS_DATA
        r = analyst_client.get(f"/north/ais{_BBOX_PARAMS}")
        assert r.status_code == 200
        assert r.get_json()["count"] == 3

    def test_ais_invalid_bbox(self, analyst_client):
        r = analyst_client.get("/north/ais?lat_min=abc")
        assert r.status_code == 400

    def test_ais_bbox_out_of_range(self, analyst_client):
        r = analyst_client.get("/north/ais?lat_min=100&lat_max=120&lon_min=0&lon_max=10")
        assert r.status_code == 400

    def test_ais_min_max_inverted(self, analyst_client):
        r = analyst_client.get("/north/ais?lat_min=80&lat_max=60&lon_min=-100&lon_max=-90")
        assert r.status_code == 400


# ── ADS-B ─────────────────────────────────────────────────────────────────────

class TestADSB:
    @patch("arctic.adsb_engine.ADSBEngine")
    def test_adsb_ok(self, MockADSB, analyst_client):
        MockADSB.return_value.fetch.return_value = _ADSB_DATA
        r = analyst_client.get(f"/north/adsb{_BBOX_PARAMS}")
        assert r.status_code == 200
        assert r.get_json()["count"] == 2

    def test_adsb_invalid_bbox(self, analyst_client):
        r = analyst_client.get("/north/adsb?lat_min=bad")
        assert r.status_code == 400


# ── Ice ───────────────────────────────────────────────────────────────────────

class TestIce:
    @patch("arctic.ice_engine.IceEngine")
    def test_ice_ok(self, MockIce, analyst_client):
        MockIce.return_value.fetch.return_value = _ICE_DATA
        r = analyst_client.get("/north/ice")
        assert r.status_code == 200


# ── Weather ───────────────────────────────────────────────────────────────────

class TestWeather:
    @patch("arctic.weather_engine.WeatherEngine")
    def test_weather_default_station(self, MockWeather, analyst_client):
        MockWeather.return_value.fetch.return_value = _WEATHER_DATA
        r = analyst_client.get("/north/weather")
        assert r.status_code == 200

    @patch("arctic.weather_engine.WeatherEngine")
    def test_weather_custom_station(self, MockWeather, analyst_client):
        MockWeather.return_value.fetch.return_value = _WEATHER_DATA
        r = analyst_client.get("/north/weather?station=CYZF")
        assert r.status_code == 200
        MockWeather.return_value.fetch.assert_called_once_with("CYZF")


# ── Infrastructure ────────────────────────────────────────────────────────────

class TestInfrastructure:
    @patch("arctic.infra_engine.InfraEngine")
    def test_infra_default_region(self, MockInfra, analyst_client):
        MockInfra.return_value.fetch.return_value = _INFRA_DATA
        r = analyst_client.get("/north/infrastructure")
        assert r.status_code == 200
        MockInfra.return_value.fetch.assert_called_once_with("nunavut")

    @patch("arctic.infra_engine.InfraEngine")
    def test_infra_custom_region(self, MockInfra, analyst_client):
        MockInfra.return_value.fetch.return_value = _INFRA_DATA
        r = analyst_client.get("/north/infrastructure?region=yukon")
        assert r.status_code == 200
        MockInfra.return_value.fetch.assert_called_once_with("yukon")


# ── Geo ───────────────────────────────────────────────────────────────────────

class TestGeo:
    @patch("arctic.geo_engine.GeoEngine")
    def test_geo_ok(self, MockGeo, analyst_client):
        MockGeo.return_value.fetch.return_value = _GEO_DATA
        r = analyst_client.get("/north/geo")
        assert r.status_code == 200
        assert r.get_json()["type"] == "FeatureCollection"


# ── Satellite ─────────────────────────────────────────────────────────────────

class TestSatellite:
    @patch("arctic.satellite_engine.SatelliteEngine")
    def test_satellite_ok(self, MockSat, analyst_client):
        MockSat.return_value.fetch.return_value = _SAT_DATA
        r = analyst_client.get(f"/north/satellite{_BBOX_PARAMS}")
        assert r.status_code == 200

    @patch("arctic.satellite_engine.SatelliteEngine")
    def test_satellite_with_aoi(self, MockSat, analyst_client):
        MockSat.return_value.fetch_aoi.return_value = _SAT_DATA
        r = analyst_client.get("/north/satellite?aoi=hudson_bay&days=7")
        assert r.status_code == 200
        MockSat.return_value.fetch_aoi.assert_called_once_with("hudson_bay", days_back=7)

    @patch("arctic.satellite_engine.SatelliteEngine")
    def test_satellite_days_clamped(self, MockSat, analyst_client):
        MockSat.return_value.fetch.return_value = _SAT_DATA
        # days=999 > 30 → clamped to default 5
        r = analyst_client.get(f"/north/satellite{_BBOX_PARAMS}&days=999")
        assert r.status_code == 200
        _, call_kwargs = MockSat.return_value.fetch.call_args
        assert call_kwargs.get("days_back") == 5

    def test_satellite_invalid_bbox(self, analyst_client):
        r = analyst_client.get("/north/satellite?lat_min=bad")
        assert r.status_code == 400


# ── Map (HTML) ────────────────────────────────────────────────────────────────

class TestMap:
    @patch("arctic.geo_engine.GeoEngine")
    def test_map_returns_html(self, MockGeo, admin_client):
        MockGeo.return_value.render_map.return_value = "<html><body>map</body></html>"
        r = admin_client.get("/north/map")
        assert r.status_code == 200
        assert b"html" in r.data.lower()


# ── Bbox validation helper ────────────────────────────────────────────────────

class TestBboxParser:
    def test_lon_out_of_range(self, analyst_client):
        r = analyst_client.get("/north/ais?lat_min=60&lat_max=80&lon_min=-200&lon_max=-60")
        assert r.status_code == 400

    def test_equal_lat_rejected(self, analyst_client):
        r = analyst_client.get("/north/ais?lat_min=60&lat_max=60&lon_min=-100&lon_max=-60")
        assert r.status_code == 400
