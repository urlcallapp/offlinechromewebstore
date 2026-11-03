"""Malicious extension semantics: blocklist, scanner states, visibility."""
import json

from unittest.mock import MagicMock, patch

from cwssync.details import ExtensionDetails
from cwssync.malicious import MaliciousChecker, MaliciousList, ScanStatus
from cwssync.sync import ChromeExtensionSync, main


def _list(path, entries):
    path.write_text(json.dumps(entries))
    return MaliciousList(path=str(path))


def test_manual_list_entries(tmp_path):
    lst = _list(tmp_path / "m.json", [{"id": "a" * 32, "reason": "manual"}, "b" * 32])
    assert "a" * 32 in lst
    assert "b" * 32 in lst
    assert "c" * 32 not in lst


def test_list_roundtrip_save(tmp_path):
    path = tmp_path / "sub" / "m.json"
    lst = MaliciousList(path=str(path))
    lst.add("d" * 32, reason="extensiontotal", risk=91)
    lst.save()
    assert MaliciousList(path=str(path)).entries["d" * 32]["risk"] == 91


def test_blocked_listed_always_blocked_without_scanner(tmp_path):
    client = MagicMock()
    client.available = False
    checker = MaliciousChecker(
        malicious_list=_list(tmp_path / "m.json", ["e" * 32]), client=client
    )
    assert checker.check("e" * 32) is ScanStatus.BLOCKED_LISTED
    assert checker.is_downloadable("e" * 32) is False
    client.get_extension_risk.assert_not_called()


def test_scanner_absent_is_downloadable_and_logged_once(tmp_path, caplog):
    client = MagicMock()
    client.available = False
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    with caplog.at_level("INFO", logger="cwssync.malicious"):
        assert checker.check("f" * 32) is ScanStatus.SCAN_UNAVAILABLE
        assert checker.check("g" * 32) is ScanStatus.SCAN_UNAVAILABLE
        assert checker.is_downloadable("f" * 32) is True
    assert caplog.text.count("risk scanning disabled") == 1


def test_high_risk_blocked_and_persisted(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.return_value = {"risk": 95}
    lst = MaliciousList(path=str(tmp_path / "m.json"))
    checker = MaliciousChecker(malicious_list=lst, client=client, threshold=70)
    assert checker.check("a" * 32) is ScanStatus.BLOCKED_RISK
    assert lst.entries["a" * 32] == {
        "id": "a" * 32, "reason": "extensiontotal", "risk": 95,
    }


def test_low_risk_is_clean(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.return_value = {"risk": 12}
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    assert checker.check("b" * 32) is ScanStatus.CLEAN
    assert checker.is_downloadable("b" * 32) is True


def test_scan_outage_is_not_clean_and_not_listed(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.side_effect = RuntimeError("api down")
    lst = MaliciousList(path=str(tmp_path / "m.json"))
    checker = MaliciousChecker(malicious_list=lst, client=client)
    assert checker.check("c" * 32) is ScanStatus.SCAN_ERROR
    assert checker.is_downloadable("c" * 32) is False
    assert "c" * 32 not in lst  # an outage never marks an extension malicious


def _syncer(tmp_path, entries, checker):
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(entries))
    return ChromeExtensionSync(
        extensions_file=str(rec),
        checker=checker,
        report_file=str(tmp_path / "report.json"),
    )


def test_sync_skips_blocked_even_when_manually_specified(tmp_path, monkeypatch):
    """A manual specified.json entry must not resurrect a blocked ID."""
    specified = tmp_path / "specified.json"
    specified.write_text(json.dumps([{"id": "h" * 32, "name": "H manual"}]))
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(specified))
    import importlib

    import cwssync.config as config

    importlib.reload(config)

    client = MagicMock()
    client.available = False
    checker = MaliciousChecker(
        malicious_list=_list(tmp_path / "m.json", [{"id": "h" * 32, "reason": "manual"}]),
        client=client,
    )
    syncer = _syncer(tmp_path, [], checker)
    with patch("cwssync.sync.get_extension_details") as details, \
         patch.object(syncer.downloader, "download") as download:
        problems = syncer.sync_extensions()
    assert problems == 0  # an intended exclusion is not a failure
    details.assert_not_called()
    download.assert_not_called()
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["extensions"] == [{"id": "h" * 32, "status": "blocked_listed"}]
    assert report["summary"]["blocked"] == 1


def test_sync_scan_outage_is_visible_failure(tmp_path):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.side_effect = RuntimeError("api down")
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    syncer = _syncer(tmp_path, [{"id": "i" * 32, "name": "I"}], checker)
    with patch("cwssync.sync.get_extension_details") as details, \
         patch.object(syncer.downloader, "download") as download:
        problems = syncer.sync_extensions()
    assert problems == 1  # nonzero: --once would exit 1
    details.assert_not_called()  # skipped before download attempt
    download.assert_not_called()
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["extensions"][0]["status"] == "scan_error"
    assert report["summary"]["scan_errors"] == 1


def test_main_once_exits_nonzero_on_scan_outage(tmp_path, monkeypatch):
    client = MagicMock()
    client.available = True
    client.get_extension_risk.side_effect = RuntimeError("api down")
    monkeypatch.setenv("CWS_SPECIFIED_EXTENSIONS_FILE", str(tmp_path / "none.json"))
    import importlib

    import cwssync.config as config

    importlib.reload(config)
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps([{"id": "j" * 32, "name": "J"}]))
    monkeypatch.setenv("CWS_RECOMMENDED_EXTENSIONS_FILE", str(rec))
    monkeypatch.setenv("CWS_SYNC_REPORT_FILE", str(tmp_path / "report.json"))
    checker = MaliciousChecker(
        malicious_list=MaliciousList(path=str(tmp_path / "m.json")), client=client
    )
    with patch("cwssync.sync.ChromeExtensionSync") as cls:
        cls.return_value = ChromeExtensionSync(
            extensions_file=str(rec),
            checker=checker,
            report_file=str(tmp_path / "report.json"),
        )
        import pytest

        with pytest.raises(SystemExit) as excinfo:
            main(["--once"])
    assert excinfo.value.code == 1


def test_cwsbuild_excludes_blocked_ids(artifact_tree):
    import importlib
    import os

    malicious = os.path.join(artifact_tree["artifacts"], "malicious_extensions.json")
    with open(malicious, "w") as handle:
        json.dump([{"id": "dhdgffkkebhmkfjojejmpbldmpobfkfo", "reason": "manual"}], handle)

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
