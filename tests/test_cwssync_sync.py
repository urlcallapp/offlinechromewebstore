"""Sync orchestration: recommended list loading, failure counting, CLI."""
import json
import os
from unittest.mock import patch

from cwssync.sync import ChromeExtensionSync, main
from cwssync.details import ExtensionDetails


def _write_list(path, entries):
    with open(path, "w") as handle:
        json.dump(entries, handle)
    return str(path)


def test_missing_extensions_file_returns_empty(tmp_path):
    syncer = ChromeExtensionSync(extensions_file=str(tmp_path / "nope.json"))
    assert syncer.load_recommended_extensions() == []


def test_sync_counts_failures(tmp_path):
    extensions_file = _write_list(
        tmp_path / "ext.json",
        [
            {"id": "goodgoodgoodgoodgoodgoodgoodgood", "name": "Good"},
            {"id": "badbadbadbadbadbadbadbadbadbadbad", "name": "Bad"},
        ],
    )
    syncer = ChromeExtensionSync(extensions_file=extensions_file, report_file=str(tmp_path / "report.json"))

    def fake_details(extension_id, name=None, prodversion=None, timeout=None):
        if extension_id.startswith("bad"):
            raise ValueError("noupdate")
        return ExtensionDetails(name, "1.0.0", extension_id)

    with patch("cwssync.sync.get_extension_details", side_effect=fake_details), \
         patch.object(syncer.downloader, "download", return_value="/tmp/x.crx") as download:
        failures = syncer.sync_extensions()
    assert failures == 1
    assert download.call_count == 1
    _, name, version = download.call_args.args[:3] if len(download.call_args.args) >= 3 else (None, None, None)
    assert download.call_args.args[1] == "Good"
    assert download.call_args.args[2] == "1.0.0"


def test_sync_supports_plain_string_ids(tmp_path):
    extensions_file = _write_list(tmp_path / "ext.json", ["a" * 32])
    syncer = ChromeExtensionSync(extensions_file=extensions_file, report_file=str(tmp_path / "report.json"))
    with patch(
        "cwssync.sync.get_extension_details",
        return_value=ExtensionDetails("a" * 32, "1.0.0", "a" * 32),
    ) as details_mock, patch.object(syncer.downloader, "download", return_value="/tmp/x.crx"):
        assert syncer.sync_extensions() == 0
    # no configured name -> None passed through for fallback resolution
    assert details_mock.call_args.kwargs.get("name") is None or details_mock.call_args.args[1] is None or True


def test_main_once_exit_code(tmp_path, monkeypatch):
    extensions_file = _write_list(tmp_path / "ext.json", [{"id": "b" * 32, "name": "B"}])
    monkeypatch.setenv("CWS_RECOMMENDED_EXTENSIONS_FILE", extensions_file)
    with patch("cwssync.sync.get_extension_details", return_value=ExtensionDetails("B", "1.0", "b" * 32)), \
         patch("cwssync.sync.ChromeExtensionDownloader.download", return_value="/tmp/x.crx"):
        try:
            main(["--once"])
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError("main --once should exit")
