import importlib
import os
import shutil
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CWSSYNC_DIR = os.path.join(REPO_ROOT, "cwsoffline", "cwssync")
CWSBUILD_DIR = os.path.join(REPO_ROOT, "cwsoffline", "cwsbuild")
CWSSTORE_DIR = os.path.join(REPO_ROOT, "cwsoffline", "cwsstore")
FIXTURE_CRX_DIR = os.path.join(
    CWSSTORE_DIR, "app", "static", "extensions"
)
TAMPERMONKEY_ID = "dhdgffkkebhmkfjojejmpbldmpobfkfo"
TRANSLATE_ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb"

for path in (CWSSYNC_DIR, CWSBUILD_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture
def artifact_tree(tmp_path, monkeypatch):
    """A minimal artifacts tree with two real CRX packages."""
    artifacts = tmp_path / "artifacts"
    assets = tmp_path / "assets"
    ext_dir = artifacts / "extensions"
    ext_dir.mkdir(parents=True)
    for ext_id, name, version in (
        (TAMPERMONKEY_ID, "Tampermonkey", "5.3.3"),
        (TRANSLATE_ID, "Google-Translate", "2.0.16"),
    ):
        target = ext_dir / ext_id / version
        target.mkdir(parents=True)
        shutil.copy(
            os.path.join(FIXTURE_CRX_DIR, f"{ext_id}.crx"),
            target / f"{ext_id}_{name}_{version}.crx",
        )
    monkeypatch.setenv("CWS_ARTIFACTS_DIR", str(artifacts))
    monkeypatch.setenv("CWS_ASSETS_DIR", str(assets))
    return {"artifacts": str(artifacts), "assets": str(assets)}


@pytest.fixture
def store_client(artifact_tree, monkeypatch):
    """FastAPI TestClient for cwsstore wired to the fixture artifacts."""
    monkeypatch.chdir(CWSSTORE_DIR)
    monkeypatch.setenv("CWS_ARTIFACTS_DIR", artifact_tree["artifacts"])
    monkeypatch.setenv("CWS_ASSETS_DIR", artifact_tree["assets"])
    if CWSSTORE_DIR not in sys.path:
        sys.path.insert(0, CWSSTORE_DIR)
    # config reads env at import time; make sure we get a fresh copy
    # Pop the whole app package: submodules survive on the parent package's
    # attributes even after their sys.modules entries are removed.
    for module in list(sys.modules):
        if module == "app" or module.startswith("app."):
            sys.modules.pop(module, None)
    from fastapi.testclient import TestClient

    import app.main

    importlib.reload(app.main)
    return TestClient(app.main.app)


def _make_store_client(monkeypatch, artifact_tree):
    monkeypatch.chdir(CWSSTORE_DIR)
    monkeypatch.setenv("CWS_ARTIFACTS_DIR", artifact_tree["artifacts"])
    monkeypatch.setenv("CWS_ASSETS_DIR", artifact_tree["assets"])
    if CWSSTORE_DIR not in sys.path:
        sys.path.insert(0, CWSSTORE_DIR)
    # Pop the whole app package: submodules survive on the parent package's
    # attributes even after their sys.modules entries are removed.
    for module in list(sys.modules):
        if module == "app" or module.startswith("app."):
            sys.modules.pop(module, None)
    from fastapi.testclient import TestClient

    import app.main

    importlib.reload(app.main)
    return TestClient(app.main.app)


@pytest.fixture
def blocked_store_client(artifact_tree, monkeypatch, built_index):
    """Store whose (stale) index still contains an ID added to the blocklist
    after the index was built."""
    import json

    with open(
        os.path.join(artifact_tree["artifacts"], "malicious_extensions.json"), "w"
    ) as handle:
        json.dump([{"id": TAMPERMONKEY_ID, "reason": "manual"}], handle)
    return _make_store_client(monkeypatch, artifact_tree)


@pytest.fixture
def built_index(artifact_tree):
    """Run cwsbuild against the fixture tree and return the parsed index."""
    import json

    import cwsbuild

    importlib.reload(cwsbuild)
    index = cwsbuild.build_index(
        src_folder=os.path.join(artifact_tree["artifacts"], "extensions"),
        dest_folder=artifact_tree["assets"],
        artifacts_dir=artifact_tree["artifacts"],
    )
    output = os.path.join(artifact_tree["artifacts"], "extensions_info.json")
    cwsbuild.save_extensions_info(index, output)
    with open(output) as handle:
        return json.load(handle)
