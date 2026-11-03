"""The air-gapped half must build and serve without sync or outbound access."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, TAMPERMONKEY_ID, TRANSLATE_ID


@pytest.mark.parametrize("with_sidecars", [False, True])
@pytest.mark.parametrize("arbitrary_filename", [False, True])
def test_build_and_store_without_network(artifact_tree, with_sidecars, arbitrary_filename):
    """Use a fresh interpreter so imports/startup are covered by the guard too."""
    artifacts = Path(artifact_tree["artifacts"])
    if arbitrary_filename:
        original = next((artifacts / "extensions" / TAMPERMONKEY_ID).rglob("*.crx"))
        original.rename(original.with_name("Internal Tool.crx"))
    if with_sidecars:
        (artifacts / "extension_metadata.json").write_text(json.dumps({
            TAMPERMONKEY_ID: {"origin": "webstore", "tags": ["tools"],
                              "description": "Transferred metadata"},
        }))
        (artifacts / "malicious_extensions.json").write_text(json.dumps([
            {"id": TRANSLATE_ID, "reason": "transferred blocklist"},
        ]))

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([
        str(Path(REPO_ROOT) / "cwsoffline" / "cwsbuild"),
        str(Path(REPO_ROOT) / "cwsoffline" / "cwsstore"),
    ])  # Deliberately exclude cwssync from the runtime path.
    env.pop("CWS_MALICIOUS_LIST_FILE", None)
    env.pop("CWS_EXTENSION_METADATA_FILE", None)
    # Even an accidentally inherited online key must not enable outbound scans.
    env["EXTENSIONTOTAL_API_KEY"] = "not-a-real-key-offline-boundary-test"
    script = r'''
import json
from pathlib import Path
import socket
import sys

def deny_network(*args, **kwargs):
    raise AssertionError("Offline components attempted outbound network access")

socket.socket.connect = deny_network
socket.socket.connect_ex = deny_network
socket.create_connection = deny_network
socket.getaddrinfo = deny_network

import cwsbuild
index = cwsbuild.build_index()
cwsbuild.save_extensions_info(index, str(Path(cwsbuild.ARTIFACTS_DIR) / "extensions_info.json"))

from fastapi.testclient import TestClient
from app.main import app
import os
from app.admin_access import assertion
key = "offline-test-signing-key-" * 3
key_file = Path(cwsbuild.ARTIFACTS_DIR) / "test-auth-key"
key_file.write_text(key)
os.environ["CWS_ADMIN_GATEWAY_SECRET_FILE"] = str(key_file)
with TestClient(app) as client:
    assert client.get("/admin").status_code == 403
    original = client.request
    def authorized(method, url, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["X-CWS-Admin-Assertion"] = assertion(key, method.upper(), url)
        return original(method, url, headers=headers, **kwargs)
    client.request = authorized
    tamper = "dhdgffkkebhmkfjojejmpbldmpobfkfo"
    translate = "aapbdbdomjkkjkaonfhkkikfgjllcleb"
    sidecars = sys.argv[1] == "True"
    entries = client.get("/json").json()
    assert {entry["extension_id"] for entry in entries} == ({tamper} if sidecars else {tamper, translate})
    entry = next(entry for entry in entries if entry["extension_id"] == tamper)
    assert entry["origin"] == ("webstore" if sidecars else "local")
    if sidecars:
        assert entry["tags"] == ["tools"]
        assert entry["description"] == "Transferred metadata"
    for route in ["/", "/app/", "/classic", "/classic/extension/" + tamper,
                  "/api/extensions/" + tamper, "/admin", "/crx", "/" + entry["image_path_url"]]:
        assert client.get(route).status_code == 200, route
    exported = client.post("/api/admin/policy/export", json={
        "base_url": "https://extensions.example.internal", "default_mode": "blocked",
        "extensions": {tamper: "force_installed"},
    })
    assert exported.status_code == 200
    assert exported.json()["extension_settings"][tamper]["override_update_url"] is True
    # The served package is the original transferred CRX, not a rebuilt package.
    expected = next((Path(cwsbuild.ARTIFACTS_DIR) / "extensions" / tamper).rglob("*.crx")).read_bytes()
    assert client.get("/download/" + tamper).content == expected
    assert client.get("/" + entry["versions"][0]["path_url"]).content == expected
    feed = client.get("/crx").text
    assert tamper in feed
    if sidecars:
        assert translate not in feed
        assert client.get("/download/" + translate).status_code == 404
    # Every static JS/CSS entry point is served locally.
    from html.parser import HTMLParser
    class Assets(HTMLParser):
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            path = attrs.get("src") if tag == "script" else attrs.get("href") if tag == "link" else None
            if path:
                assert path.startswith("/"), path
                assert client.get(path).status_code == 200, path
    Assets().feed(client.get("/").text)
assert not any(name == "cwssync" or name.startswith("cwssync.") for name in sys.modules)
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(with_sidecars)],
        cwd=Path(REPO_ROOT) / "cwsoffline" / "cwsstore",
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
