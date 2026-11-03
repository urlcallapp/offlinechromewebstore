"""Unit tests for cwssync.chrome_version.get_latest_chrome_version."""
import json

import requests

from cwssync import chrome_version


class FakeResponse:
    def __init__(self, payload=None, status=200, raw_body=None, json_error=None):
        self._payload = payload
        self.status_code = status
        self._raw_body = raw_body
        self._json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


def patch_get(monkeypatch, response=None, error=None):
    def fake_get(url, timeout):
        if error is not None:
            raise error
        assert "platforms/linux/channels/stable/versions" in url
        return response

    monkeypatch.setattr(requests, "get", fake_get)


def test_returns_latest_stable_version(monkeypatch):
    payload = {"versions": [
        {"version": "141.0.7390.65"},
        {"version": "142.0.7444.59"},
        {"version": "141.0.7390.123"},
    ]}
    patch_get(monkeypatch, FakeResponse(payload))
    assert chrome_version.get_latest_chrome_version() == "142.0.7444.59"


def test_http_error_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse(status=503))
    assert chrome_version.get_latest_chrome_version() is None


def test_connection_error_returns_none(monkeypatch):
    patch_get(monkeypatch, error=requests.ConnectionError("no route"))
    assert chrome_version.get_latest_chrome_version() is None


def test_invalid_json_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse(json_error=json.JSONDecodeError("bad", "doc", 0)))
    assert chrome_version.get_latest_chrome_version() is None


def test_non_dict_payload_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse(["142.0.0.0"]))
    assert chrome_version.get_latest_chrome_version() is None


def test_non_list_versions_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse({"versions": "142.0.0.0"}))
    assert chrome_version.get_latest_chrome_version() is None


def test_empty_versions_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse({"versions": []}))
    assert chrome_version.get_latest_chrome_version() is None


def test_unparsable_version_is_skipped_not_fatal(monkeypatch):
    payload = {"versions": [
        {"version": "not-a-version"},
        {"version": "142.0.7444.59"},
        "junk-entry",
        {"no_version": True},
    ]}
    patch_get(monkeypatch, FakeResponse(payload))
    assert chrome_version.get_latest_chrome_version() == "142.0.7444.59"


def test_all_versions_unparsable_returns_none(monkeypatch):
    patch_get(monkeypatch, FakeResponse({"versions": [{"version": "beta.latest"}]}))
    assert chrome_version.get_latest_chrome_version() is None


def test_platform_is_interpolated(monkeypatch):
    seen = {}

    def fake_get(url, timeout):
        seen["url"] = url
        return FakeResponse({"versions": [{"version": "142.0.0.0"}]})

    monkeypatch.setattr(requests, "get", fake_get)
    assert chrome_version.get_latest_chrome_version(platform="win64") == "142.0.0.0"
    assert "platforms/win64/" in seen["url"]
