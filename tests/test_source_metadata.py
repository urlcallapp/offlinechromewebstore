"""Classification in the store source definitions: tags, origin (webstore /
in-house / local) and description overrides flow sync -> build -> index ->
store. Taxonomy only; the malicious blocklist stays the security filter."""
import json

from unittest.mock import patch

from conftest import TAMPERMONKEY_ID, TRANSLATE_ID
from cwssync.details import ExtensionDetails
from cwssync.sync import ChromeExtensionSync


def _recommended(tmp_path, entries):
    path = tmp_path / "rec.json"
    path.write_text(json.dumps(entries))
    return str(path)


def _syncer(tmp_path, entries):
    return ChromeExtensionSync(
        extensions_file=_recommended(tmp_path, entries),
        report_file=str(tmp_path / "report.json"),
    )


def test_entry_parsing_backwards_compatible(tmp_path, monkeypatch):
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    syncer = _syncer(tmp_path, [
        "a" * 32,                                # plain ID string
        {"id": "b" * 32, "name": "B"},           # legacy object
        {"id": "c" * 32, "name": "C", "tags": ["devtools"], "origin": "in-house"},
    ])
    by_id = {e["id"]: e for e in syncer.load_extensions()}
    assert by_id["a" * 32] == {"id": "a" * 32, "tags": [], "origin": "webstore"}
    assert by_id["b" * 32]["origin"] == "webstore"
    assert by_id["c" * 32]["tags"] == ["devtools"]
    assert by_id["c" * 32]["origin"] == "in-house"


def test_non_list_tags_become_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    syncer = _syncer(tmp_path, [{"id": "a" * 32, "tags": "not-a-list"}])
    assert syncer.load_extensions()[0]["tags"] == []


def _in_house_crx(tmp_path, monkeypatch, extension_id):
    artifacts = tmp_path / "artifacts"
    monkeypatch.setenv("CWS_ARTIFACTS_DIR", str(artifacts))
    crx_dir = artifacts / "extensions" / extension_id / "1.0"
    crx_dir.mkdir(parents=True)
    (crx_dir / f"{extension_id}_tool_1.0.crx").write_bytes(b"crx")


def test_sync_skips_download_for_in_house(tmp_path, monkeypatch):
    """In-house entries are classified, not fetched from the web store."""
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    monkeypatch.setenv("CWS_MALICIOUS_LIST_FILE", str(tmp_path / "none2.json"))
    _in_house_crx(tmp_path, monkeypatch, "a" * 32)
    metadata_path = tmp_path / "extension_metadata.json"
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", str(metadata_path))
    syncer = _syncer(tmp_path, [
        {"id": "a" * 32, "name": "Internal Tool", "origin": "in-house",
         "tags": ["internal"], "description": "Built by us."},
        {"id": "b" * 32, "name": "Store Ext", "tags": ["devtools"]},
    ])
    with patch("cwssync.sync.get_extension_details",
               side_effect=lambda eid, name=None: ExtensionDetails(name or eid, "1.0", eid)) as details, \
         patch.object(syncer.downloader, "download", return_value="/tmp/x.crx"), \
         patch.object(syncer.checker, "check", return_value=__import__("cwssync.malicious", fromlist=["ScanStatus"]).ScanStatus.CLEAN), \
         patch.object(syncer.checker.malicious_list, "save"):
        assert syncer.sync_extensions() == 0
    # only the webstore entry hit the network
    assert [c.args[0] for c in details.call_args_list] == ["b" * 32]
    metadata = json.loads(metadata_path.read_text())
    assert metadata["a" * 32] == {
        "origin": "in-house", "tags": ["internal"], "description": "Built by us."
    }
    assert metadata["b" * 32] == {"origin": "webstore", "tags": ["devtools"]}
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["summary"]["in_house"] == 1
    assert report["summary"]["mirrored"] == 1


def test_metadata_scoped_to_mirrored_and_in_house(tmp_path, monkeypatch):
    """Blocked IDs never receive metadata downstream."""
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    monkeypatch.setenv("CWS_MALICIOUS_LIST_FILE", str(tmp_path / "none2.json"))
    metadata_path = tmp_path / "extension_metadata.json"
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", str(metadata_path))
    syncer = _syncer(tmp_path, [
        {"id": "a" * 32, "tags": ["ok"]},
        {"id": "b" * 32, "tags": ["blocked-tag"]},
    ])
    from cwssync.malicious import ScanStatus

    def fake_check(extension_id):
        return ScanStatus.BLOCKED_LISTED if extension_id == "b" * 32 else ScanStatus.CLEAN

    with patch.object(syncer.checker, "check", side_effect=fake_check), \
         patch("cwssync.sync.get_extension_details",
               side_effect=lambda eid, name=None: ExtensionDetails(name or eid, "1.0", eid)), \
         patch.object(syncer.downloader, "download", return_value="/tmp/x.crx"), \
         patch.object(syncer.checker.malicious_list, "save"):
        syncer.sync_extensions()
    assert set(json.loads(metadata_path.read_text())) == {"a" * 32}


def test_build_merges_classification(artifact_tree, monkeypatch):
    import importlib
    import os

    import cwsbuild

    metadata_file = os.path.join(artifact_tree["artifacts"], "extension_metadata.json")
    with open(metadata_file, "w") as handle:
        json.dump({
            TAMPERMONKEY_ID: {"origin": "in-house", "tags": ["automation"],
                              "description": "Our build."},
        }, handle)
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", metadata_file)
    importlib.reload(cwsbuild)
    index = cwsbuild.build_index(
        src_folder=os.path.join(artifact_tree["artifacts"], "extensions"),
        dest_folder=artifact_tree["assets"],
        artifacts_dir=artifact_tree["artifacts"],
    )
    by_id = {entry["extension_id"]: entry for entry in index}
    tamper = by_id[TAMPERMONKEY_ID]
    assert tamper["tags"] == ["automation"]
    assert tamper["origin"] == "in-house"
    assert tamper["description"] == "Our build."
    # no source entry: manifest description used (the Translate fixture's
    # is an __MSG_*__ placeholder that resolves to ""), unclassified origin
    translate = by_id[TRANSLATE_ID]
    assert translate["tags"] == []
    assert translate["origin"] == "local"
    assert translate["description"] == ""
def test_in_house_missing_crx_reported(tmp_path, monkeypatch):
    """A declared in-house extension without a CRX is not available."""
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    monkeypatch.setenv("CWS_MALICIOUS_LIST_FILE", str(tmp_path / "none2.json"))
    monkeypatch.setenv("CWS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    metadata_path = tmp_path / "extension_metadata.json"
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", str(metadata_path))
    syncer = _syncer(tmp_path, [
        {"id": "a" * 32, "origin": "in-house", "tags": ["internal"]},
    ])
    assert syncer.sync_extensions() == 1
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["extensions"][0]["status"] == "in_house_missing"
    assert report["summary"]["in_house"] == 0
    assert report["summary"]["failures"] == 1
    # no metadata, so nothing can surface downstream
    assert json.loads(metadata_path.read_text()) == {}


def test_in_house_blocked_by_local_list(tmp_path, monkeypatch):
    """The blocklist applies to in-house entries: no metadata, no CRX needed."""
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    blocklist = tmp_path / "malicious.json"
    blocklist.write_text(json.dumps([{"id": "a" * 32, "reason": "manual"}]))
    metadata_path = tmp_path / "extension_metadata.json"
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", str(metadata_path))
    syncer = _syncer(tmp_path, [
        {"id": "a" * 32, "origin": "in-house", "tags": ["internal"]},
    ])
    from cwssync.malicious import MaliciousList
    syncer.checker.malicious_list = MaliciousList(str(blocklist))
    with patch.object(syncer.checker.malicious_list, "save"):
        assert syncer.sync_extensions() == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["extensions"][0]["status"] == "blocked_listed"
    assert report["summary"]["blocked"] == 1
    assert json.loads(metadata_path.read_text()) == {}


def test_build_ignores_metadata_without_crx(artifact_tree, monkeypatch):
    """Metadata for an ID with no CRX in the tree never enters the index."""
    import importlib
    import os

    import cwsbuild

    ghost = "f" * 32
    metadata_file = os.path.join(artifact_tree["artifacts"], "extension_metadata.json")
    with open(metadata_file, "w") as handle:
        json.dump({ghost: {"origin": "in-house", "tags": ["ghost"]}}, handle)
    monkeypatch.setenv("CWS_EXTENSION_METADATA_FILE", metadata_file)
    importlib.reload(cwsbuild)
    index = cwsbuild.build_index(
        src_folder=os.path.join(artifact_tree["artifacts"], "extensions"),
        dest_folder=artifact_tree["assets"],
        artifacts_dir=artifact_tree["artifacts"],
    )
    assert ghost not in {entry["extension_id"] for entry in index}
