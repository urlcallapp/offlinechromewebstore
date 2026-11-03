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


def test_latest_version_owns_metadata_and_clean_assets(tmp_path):
    import json
    import zipfile
    from crx_helpers import crx3, key_id
    ext_id = key_id()
    artifacts = tmp_path / 'artifacts'
    assets = tmp_path / 'assets'
    for version, name in [('2.0', 'Newest'), ('1.0', 'Oldest')]:
        folder = artifacts / 'extensions' / ext_id / version
        folder.mkdir(parents=True)
        with zipfile.ZipFile(folder / f'{ext_id}_Test_{version}.crx', 'w') as archive:
            archive.writestr('manifest.json', json.dumps({'name': name, 'version': version, 'description': name, 'icons': {'128': 'icon.png'}}))
            archive.writestr('icon.png', name)
            archive.writestr(name + '.txt', name)
        package = folder / f'{ext_id}_Test_{version}.crx'
        package.write_bytes(crx3(package.read_bytes()))
    index = cwsbuild.build_index(dest_folder=str(assets), artifacts_dir=str(artifacts))
    assert index[0]['name'] == index[0]['description'] == 'Newest'
    assert [v['version'] for v in index[0]['versions']] == ['2.0', '1.0']
    assert (assets / ext_id / 'icon.png').read_text() == 'Newest'
    assert not (assets / ext_id / 'Oldest.txt').exists()


def test_icon_path_cannot_escape_extension(tmp_path):
    (tmp_path / 'secret').write_text('secret')
    dest = tmp_path / 'extension'
    dest.mkdir()
    assert cwsbuild.resolve_icon({'icons': {'128': '../secret'}}, str(dest), 'a' * 32) == cwsbuild.FALLBACK_ICON_URL


def test_consume_intake_moves_valid_and_keeps_invalid(tmp_path, caplog):
    import cwsbuild
    from crx_helpers import crx3, key_id
    from test_crx_identity import archive

    intake = tmp_path / "intake"
    artifacts = tmp_path / "artifacts"
    upload_dir = intake / key_id() / "2.1"
    upload_dir.mkdir(parents=True)
    valid = upload_dir / f"{key_id()}_Internal-Tool_2.1.crx"
    package = crx3(archive(version="2.1"))
    valid.write_bytes(package)
    junk_dir = intake / "junk"
    junk_dir.mkdir()
    junk = junk_dir / "broken.crx"
    junk.write_bytes(b"not a crx")

    consumed = cwsbuild.consume_intake(str(intake), str(artifacts))
    assert consumed == 1
    target = artifacts / "extensions" / key_id() / "2.1" / valid.name
    assert target.is_file() and target.read_bytes() == package
    assert not valid.exists()
    assert junk.exists()  # invalid upload stays for admin review
    assert "Refusing staged upload" in caplog.text

    index = cwsbuild.build_index(artifacts_dir=str(artifacts), dest_folder=str(tmp_path / "assets"))
    entry = next(item for item in index if item["extension_id"] == key_id())
    assert entry["versions"][0]["version"] == "2.1"
    assert entry["versions"][0]["path_url"].startswith("artifacts/extensions/")


def test_consume_intake_unset_is_noop(tmp_path):
    import cwsbuild
    assert cwsbuild.consume_intake("", str(tmp_path)) == 0


def test_consume_intake_rechecks_current_blocklist(tmp_path):
    import cwsbuild, json
    from crx_helpers import crx3, key_id
    from test_crx_identity import archive
    intake = tmp_path / 'intake'; intake.mkdir()
    staged = intake / 'internal.crx'; staged.write_bytes(crx3(archive()))
    artifacts = tmp_path / 'artifacts'; artifacts.mkdir()
    (artifacts / 'malicious_extensions.json').write_text(json.dumps([key_id()]))
    assert cwsbuild.consume_intake(str(intake), str(artifacts)) == 0
    assert staged.exists()
