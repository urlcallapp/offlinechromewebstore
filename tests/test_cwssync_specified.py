"""Manually specified extensions list (artifacts/specified.json)."""
import json

from unittest.mock import patch

from cwssync.details import ExtensionDetails
from cwssync.sync import ChromeExtensionSync


def _write(path, entries):
    path.write_text(json.dumps(entries))
    return str(path)


def test_no_specified_file_means_recommended_only(tmp_path, monkeypatch):
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "specified.json"))
    import importlib

    import cwssync.config as config

    importlib.reload(config)
    recommended = _write(tmp_path / "rec.json", [{"id": "a" * 32, "name": "A"}])
    syncer = ChromeExtensionSync(extensions_file=recommended)
    assert [e["id"] for e in syncer.load_extensions()] == ["a" * 32]


def test_specified_entries_merge_and_override(tmp_path, monkeypatch):
    specified_path = tmp_path / "specified.json"
    _write(specified_path, [{"id": "a" * 32, "name": "Custom A"}, "b" * 32])
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(specified_path))
    import importlib

    import cwssync.config as config

    importlib.reload(config)
    recommended = _write(
        tmp_path / "rec.json", [{"id": "a" * 32, "name": "Recommended A"}]
    )
    syncer = ChromeExtensionSync(extensions_file=recommended)
    merged = {e["id"] if isinstance(e, dict) else e: e for e in syncer.load_extensions()}
    assert set(merged) == {"a" * 32, "b" * 32}
    # manual entry overrides the recommended name for the same ID
    assert merged["a" * 32]["name"] == "Custom A"


def test_sync_uses_merged_list(tmp_path, monkeypatch):
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    import importlib

    import cwssync.config as config

    importlib.reload(config)
    recommended = _write(tmp_path / "rec.json", [{"id": "a" * 32, "name": "A"}])
    syncer = ChromeExtensionSync(extensions_file=recommended)
    with patch("cwssync.sync.get_extension_details", return_value=ExtensionDetails("A", "1.0", "a" * 32)), \
         patch.object(syncer.downloader, "download", return_value="/tmp/x.crx"):
        assert syncer.sync_extensions() == 0
