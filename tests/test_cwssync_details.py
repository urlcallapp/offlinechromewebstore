"""Version resolution via the update2 updatecheck API."""
from unittest.mock import MagicMock, patch

import pytest

from cwssync import details

UPDATECHECK_OK = b"""<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="abc" status="ok">
    <updatecheck status="ok">
      <urls><url codebase="https://example.com/x.crx"/></urls>
      <manifest version="4.9.109">
        <packages><package name="x.crx" hash_sha256="deadbeef" size="1" required="true"/></packages>
      </manifest>
    </updatecheck>
  </app>
</gupdate>"""

UPDATECHECK_NOUPDATE = b"""<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="abc" status="ok"><updatecheck status="noupdate"/></app>
</gupdate>"""


def _response(content, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.content = content
    response.raise_for_status = MagicMock()
    return response


def test_version_from_updatecheck():
    with patch("cwssync.details.requests.get", return_value=_response(UPDATECHECK_OK)) as get:
        version = details.get_extension_version("abc", prodversion="131.0.0.0")
    assert version == "4.9.109"
    params = get.call_args.kwargs["params"]
    assert params["response"] == "updatecheck"
    assert params["x"] == "id=abc&uc"


def test_noupdate_raises():
    with patch("cwssync.details.requests.get", return_value=_response(UPDATECHECK_NOUPDATE)):
        with pytest.raises(ValueError, match="noupdate"):
            details.get_extension_version("abc", prodversion="131.0.0.0")


def test_details_prefer_configured_name():
    with patch("cwssync.details.requests.get", return_value=_response(UPDATECHECK_OK)):
        result = details.get_extension_details("abc", name="Tampermonkey", prodversion="131.0.0.0")
    assert result.name == "Tampermonkey"
    assert result.version == "4.9.109"
    assert result.extension_id == "abc"


def test_details_fall_back_to_id_when_name_unknown():
    with patch("cwssync.details.requests.get", return_value=_response(UPDATECHECK_OK)), \
         patch("cwssync.details.get_extension_name", return_value=None):
        result = details.get_extension_details("abc", prodversion="131.0.0.0")
    assert result.name == "abc"
