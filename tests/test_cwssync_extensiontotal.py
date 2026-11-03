"""ExtensionTotal client: import-safe without a key, request shape with one."""
from unittest.mock import MagicMock, patch

import pytest

from cwssync.extensiontotal import ExtensionTotalClient


def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("EXTENSIONTOTAL_API_KEY", raising=False)
    client = ExtensionTotalClient()
    assert client.available is False
    with pytest.raises(RuntimeError, match="EXTENSIONTOTAL_API_KEY"):
        client.get_extension_risk("abc")


def test_risk_request_shape(monkeypatch):
    monkeypatch.setenv("EXTENSIONTOTAL_API_KEY", "secret-key")
    client = ExtensionTotalClient()
    response = MagicMock()
    response.json.return_value = {"risk": 42}
    response.raise_for_status = MagicMock()
    with patch("cwssync.extensiontotal.requests.post", return_value=response) as post:
        result = client.get_extension_risk("abc")
    assert result == {"risk": 42}
    assert post.call_args.kwargs["json"] == {"q": "abc"}
    assert post.call_args.kwargs["headers"]["X-API-Key"] == "secret-key"
    assert client.available is True
