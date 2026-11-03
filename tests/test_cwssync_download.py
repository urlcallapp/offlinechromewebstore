"""CRX download behavior: layout, caching, force mode, error handling."""
import os
from unittest.mock import MagicMock, patch

from cwssync.download import ChromeExtensionDownloader, slugify_name

EXT_ID = "dhdgffkkebhmkfjojejmpbldmpobfkfo"


def _stream_response(status_code=200, payload=b"CRXDATA"):
    response = MagicMock()
    response.status_code = status_code
    response.iter_content = MagicMock(return_value=iter([payload]))
    return response


def test_slugify():
    assert slugify_name("Dark Reader") == "Dark-Reader"
    assert slugify_name("  ") == "extension"


def test_download_writes_expected_path(tmp_path):
    downloader = ChromeExtensionDownloader(artifacts_dir=str(tmp_path), prodversion="131.0.0.0")
    with patch("cwssync.download.requests.get", return_value=_stream_response()):
        path = downloader.download(EXT_ID, "Dark Reader", "4.9.1")
    expected = tmp_path / "extensions" / EXT_ID / "4.9.1" / f"{EXT_ID}_Dark-Reader_4.9.1.crx"
    assert path == str(expected)
    assert open(path, "rb").read() == b"CRXDATA"


def test_existing_file_is_reused(tmp_path):
    downloader = ChromeExtensionDownloader(artifacts_dir=str(tmp_path), prodversion="131.0.0.0")
    with patch("cwssync.download.requests.get", return_value=_stream_response()) as get:
        downloader.download(EXT_ID, "Dark Reader", "4.9.1")
        assert get.call_count == 1
        downloader.download(EXT_ID, "Dark Reader", "4.9.1")
        assert get.call_count == 1  # no second request


def test_force_redownloads(tmp_path):
    downloader = ChromeExtensionDownloader(artifacts_dir=str(tmp_path), prodversion="131.0.0.0")
    with patch("cwssync.download.requests.get", return_value=_stream_response()) as get:
        downloader.download(EXT_ID, "Dark Reader", "4.9.1", force=True)
        downloader.download(EXT_ID, "Dark Reader", "4.9.1", force=True)
        assert get.call_count == 2


def test_http_error_returns_none(tmp_path):
    downloader = ChromeExtensionDownloader(artifacts_dir=str(tmp_path), prodversion="131.0.0.0")
    with patch("cwssync.download.requests.get", return_value=_stream_response(status_code=404)):
        assert downloader.download(EXT_ID, "Dark Reader", "4.9.1") is None
    assert not os.path.exists(downloader.crx_path(EXT_ID, "Dark-Reader", "4.9.1"))
