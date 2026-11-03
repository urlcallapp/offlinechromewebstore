"""Malicious extension list: local blocklist, ExtensionTotal risk, persistence."""
import json

from unittest.mock import MagicMock, patch

from cwssync.details import ExtensionDetails
from cwssync.malicious import MaliciousChecker, MaliciousList
from cwssync.sync import ChromeExtensionSync


def test_manual_list_entries(tmp_path):
    path = tmp_path / "malicious_extensions.json"
    path.write_text(json.dumps([{"id": "a" * 32, "reason": "manual"}, "b" * 32]))
    lst = MaliciousList(path=str(path))
    assert "a" * 32 in lst
    assert "b" * 32 in lst
    assert "c" * 32 not in lst


def test_list_roundtrip_save(tmp_path):
    path = tmp_path / "sub" / "malicious_extensions.json"
    lst = MaliciousList(path=str(path))
    lst.add("d" * 32, reason="extensiontotal", risk=91)
    lst.save()
    reloaded = MaliciousList(path=str(path))
    assert reloaded.entries["d" * 32]["risk"] == 91


def test_checker_uses_local_list_without_api(tmp_path):
    path = tmp_path / "malicious.json"
    path.write_text(json.dumps(["e" * 32]))
    client = MagicMock()
    client.available = False
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(path)), client=client
    )
    assert checker.is_malicious("e" * 32) is True
    assert checker.is_malicious("f" * 32) is False
    client.get_extension_risk.assert_not_called()


def test_checker_marks_high_risk_and_persists(tmp_path):
    path = tmp_path / "malicious.json"
    client = MagicMock()
    client.available = True
    client.get_extension_risk.return_value = {"risk": 95}
    lst = MaliciousList(path=str(path))
    checker = MaliciousChecker(malicious_list=lst, client=client, threshold=70)
    assert checker.is_malicious("0".replace("0", "a") * 32) is True
    assert lst.entries["a" * 32]["reason"] == "extensiontotal"
    assert lst.entries["a" * 32]["risk"] == 95


def test_checker_passes_low_risk(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.return_value = {"risk": 12}
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    assert checker.is_malicious("b" * 32) is False


def test_checker_fails_open_on_api_error(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.side_effect = RuntimeError("api down")
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    assert checker.is_malicious("c" * 32) is False


def test_sync_skips_malicious(tmp_path):
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps([{"id": "g" * 32, "name": "G"}, {"id": "h" * 32, "name": "H"}]))
    checker = MagicMock()
    checker.is_malicious.side_effect = lambda ext_id: ext_id == "h" * 32
    checker.malicious_list = MagicMock()
    syncer = ChromeExtensionSync(extensions_file=str(rec), checker=checker)
    with patch("cwssync.sync.get_extension_details", return_value=ExtensionDetails("G", "1.0", "g" * 32)) as details, \
         patch.object(syncer.downloader, "download", return_value="/tmp/x.crx"):
        assert syncer.sync_extensions() == 0
    # only the clean extension was resolved and downloaded
    assert details.call_count == 1
    checker.malicious_list.save.assert_called_once()


def test_cwsbuild_excludes_malicious_ids(artifact_tree):
    import importlib
    import json as _json
    import os

    malicious = os.path.join(artifact_tree["artifacts"], "malicious_extensions.json")
    with open(malicious, "w") as handle:
        _json.dump([{"id": "dhdgffkkebhmkfjojejmpbldmpobfkfo", "reason": "manual"}], handle)

    import cwsbuild

    importlib.reload(cwsbuild)
    index = cwsbuild.build_index(
        src_folder=os.path.join(artifact_tree["artifacts"], "extensions"),
        dest_folder=artifact_tree["assets"],
        artifacts_dir=artifact_tree["artifacts"],
    )
    ids = {entry["extension_id"] for entry in index}
    assert "dhdgffkkebhmkfjojejmpbldmpobfkfo" not in ids
    assert "aapbdbdomjkkjkaonfhkkikfgjllcleb" in ids
