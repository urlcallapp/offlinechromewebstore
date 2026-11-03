"""cwsbuild index building against real CRX fixtures."""
import os

import cwsbuild
from conftest import TAMPERMONKEY_ID, TRANSLATE_ID


def test_parse_crx_filename():
    ext_id, name, version = cwsbuild.parse_crx_filename(
        "dhdgffkkebhmkfjojejmpbldmpobfkfo_Dark-Reader_4.9.1.crx"
    )
    assert (ext_id, name, version) == (
        "dhdgffkkebhmkfjojejmpbldmpobfkfo",
        "Dark Reader",
        "4.9.1",
    )
    ext_id, name, version = cwsbuild.parse_crx_filename("aapbdbdomjkkjkaonfhkkikfgjllcleb.crx")
    assert ext_id == "aapbdbdomjkkjkaonfhkkikfgjllcleb"
    assert name == "" and version == ""


def test_valid_extension_id():
    assert cwsbuild.is_valid_extension_id("a" * 32)
    assert not cwsbuild.is_valid_extension_id("z" * 32)  # only a-p allowed
    assert not cwsbuild.is_valid_extension_id("a" * 31)


def test_i18n_placeholders():
    assert cwsbuild._is_i18n_placeholder("__MSG_appName__")
    assert cwsbuild._is_i18n_placeholder("")
    assert not cwsbuild._is_i18n_placeholder("Dark Reader")


def test_build_index_from_real_crx(built_index, artifact_tree):
    by_id = {entry["extension_id"]: entry for entry in built_index}
    assert set(by_id) == {TAMPERMONKEY_ID, TRANSLATE_ID}

    tamper = by_id[TAMPERMONKEY_ID]
    assert tamper["name"] == "Tampermonkey"
    assert tamper["versions"][0]["version"] == "5.3.3"
    assert tamper["versions"][0]["path_url"].startswith("artifacts/extensions/")
    # icon URL is served relative to the store root and the file exists on disk
    icon_rel = tamper["image_path_url"].removeprefix("assets/")
    assert os.path.exists(os.path.join(artifact_tree["assets"], icon_rel))


def test_versions_sorted_newest_first(built_index):
    for entry in built_index:
        versions = [v["version"] for v in entry["versions"]]
        assert versions == sorted(
            versions, key=cwsbuild._version_sort_key, reverse=True
        )


def test_unreadable_crx_is_skipped(artifact_tree):
    bad = os.path.join(
        artifact_tree["artifacts"], "extensions", "c" * 32 + "_Broken_1.0.crx"
    )
    with open(bad, "w") as handle:
        handle.write("not a crx")
    index = cwsbuild.build_index(
        src_folder=os.path.join(artifact_tree["artifacts"], "extensions"),
        dest_folder=artifact_tree["assets"],
        artifacts_dir=artifact_tree["artifacts"],
    )
    assert all(entry["extension_id"] != "c" * 32 for entry in index)
    assert len(index) == 2
