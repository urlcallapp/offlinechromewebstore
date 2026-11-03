"""cwsstore HTTP endpoints against a built fixture index."""
import json
import os

from conftest import TAMPERMONKEY_ID, TRANSLATE_ID

UPDATECHECK_REQUEST = f"""<?xml version="1.0" encoding="UTF-8"?>
<request protocol="3.0">
  <app appid="{TAMPERMONKEY_ID}"><updatecheck/></app>
  <app appid="{"a" * 31}b"><updatecheck/></app>
</request>"""


def test_homepage_lists_extensions(store_client, built_index):
    response = store_client.get("/classic")
    assert response.status_code == 200
    assert "Tampermonkey" in response.text
    assert "Google Translate" in response.text


def test_json_route(store_client, built_index):
    response = store_client.get("/json")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_crx_feed_lists_all_on_get(store_client, built_index):
    response = store_client.get("/crx")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    assert TAMPERMONKEY_ID in response.text
    assert TRANSLATE_ID in response.text
    assert 'codebase="http://testserver/artifacts/extensions/' in response.text


def test_crx_feed_filters_posted_appids(store_client, built_index):
    response = store_client.post("/crx", content=UPDATECHECK_REQUEST)
    assert response.status_code == 200
    assert TAMPERMONKEY_ID in response.text
    assert TRANSLATE_ID not in response.text
    assert "a" * 31 + "b" not in response.text  # unknown IDs are not listed


def test_extension_detail_page(store_client, built_index):
    response = store_client.get(f"/extension/{TAMPERMONKEY_ID}")
    assert response.status_code == 200
    assert "Tampermonkey" in response.text
    assert "5.3.3" in response.text


def test_extension_detail_missing(store_client, built_index):
    assert store_client.get("/extension/" + "a" * 32).status_code == 404


def test_api_extension(store_client, built_index):
    response = store_client.get(f"/api/extensions/{TAMPERMONKEY_ID}")
    assert response.status_code == 200
    assert response.json()["name"] == "Tampermonkey"


def test_download_serves_crx(store_client, built_index):
    response = store_client.get(f"/download/{TAMPERMONKEY_ID}")
    assert response.status_code == 200
    assert len(response.content) > 1000
    assert response.headers["content-type"] == "application/octet-stream"


def test_static_artifacts_and_assets_served(store_client, built_index):
    crx = store_client.get(
        f"/artifacts/extensions/{TAMPERMONKEY_ID}/5.3.3/"
        f"{TAMPERMONKEY_ID}_Tampermonkey_5.3.3.crx"
    )
    assert crx.status_code == 200
    icon = store_client.get(
        f"/assets/{TAMPERMONKEY_ID}/images/icon128.png"
    )
    assert icon.status_code == 200


def test_blocked_extension_hidden_everywhere(blocked_store_client):
    """A stale index must not leak a blocked ID through any route."""
    client = blocked_store_client
    crx_rel = (
        f"artifacts/extensions/{TAMPERMONKEY_ID}/5.3.3/"
        f"{TAMPERMONKEY_ID}_Tampermonkey_5.3.3.crx"
    )
    assert TAMPERMONKEY_ID not in client.get("/").text
    assert all(
        e["extension_id"] != TAMPERMONKEY_ID for e in client.get("/json").json()
    )
    assert TAMPERMONKEY_ID not in client.get("/crx").text
    assert client.get(f"/extension/{TAMPERMONKEY_ID}").status_code == 404
    assert client.get(f"/api/extensions/{TAMPERMONKEY_ID}").status_code == 404
    assert client.get(f"/download/{TAMPERMONKEY_ID}").status_code == 404
    # the raw CRX bytes and extracted assets are also refused
    assert client.get(f"/{crx_rel}").status_code == 404
    assert client.get(
        f"/assets/{TAMPERMONKEY_ID}/images/icon128.png"
    ).status_code == 404
    # the clean extension still works everywhere
    assert client.get(f"/download/{TRANSLATE_ID}").status_code == 200
    assert client.get(
        "/artifacts/extensions/"
        f"{TRANSLATE_ID}/2.0.16/{TRANSLATE_ID}_Google-Translate_2.0.16.crx"
    ).status_code == 200


def test_artifact_traversal_is_refused(blocked_store_client):
    assert blocked_store_client.get("/artifacts/..%2F..%2Fetc%2Fpasswd").status_code in (400, 404)
    assert blocked_store_client.get("/assets/..%2F..%2Fetc%2Fpasswd").status_code in (400, 404)


def test_crx_feed_get_x_param_filters(store_client, built_index):
    response = store_client.get(f"/crx?x=id%3D{TAMPERMONKEY_ID}%26uc")
    assert response.status_code == 200
    assert TAMPERMONKEY_ID in response.text
    assert TRANSLATE_ID not in response.text


def test_crx_feed_has_ok_statuses(store_client, built_index):
    text = store_client.get("/crx").text
    assert text.startswith("<?xml")
    assert f'<app appid="{TAMPERMONKEY_ID}" status="ok">' in text
    assert '<updatecheck status="ok" codebase=' in text
