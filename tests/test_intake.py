"""First-party CRX upload intake: structural validation and staging only."""
import io
import json
import zipfile

import pytest
from conftest import _make_store_client, artifact_tree  # noqa: F401
from crx_helpers import crx3, key_id


def archive(version='2.1', name='Internal Tool'):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as package:
        package.writestr('manifest.json', json.dumps({'name': name, 'version': version}))
    return stream.getvalue()


@pytest.fixture
def intake_client(artifact_tree, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setenv('CWS_INTAKE_DIR', str(tmp_path / 'intake'))
    return _make_store_client(monkeypatch, artifact_tree)


def upload(client, payload, content_type='application/octet-stream'):
    return client.post('/api/admin/intake/upload', content=payload,
                       headers={'Content-Type': content_type})


def test_upload_stages_valid_crx(intake_client, tmp_path):
    package = crx3(archive())
    response = upload(intake_client, package)
    assert response.status_code == 200
    staged = response.json()['staged']
    assert staged['extension_id'] == key_id()
    assert staged['version'] == '2.1'
    assert staged['name'] == 'Internal Tool'
    path = tmp_path / 'intake' / key_id() / '2.1' / staged['filename']
    assert path.read_bytes() == package


def test_upload_rejects_non_crx(intake_client):
    response = upload(intake_client, archive())
    assert response.status_code == 422


def test_upload_rejects_bad_manifest_version(intake_client):
    response = upload(intake_client, crx3(archive(version='1.0-beta')))
    assert response.status_code == 422


def test_upload_requires_octet_stream(intake_client):
    response = upload(intake_client, crx3(archive()), content_type='application/json')
    assert response.status_code == 415


def test_upload_rejects_blocklisted(intake_client, artifact_tree, monkeypatch):  # noqa: F811
    blocked = [{"id": key_id()}]
    import app.blocklist as blocklist
    list_file = tmp_blocklist = artifact_tree['artifacts'] + '/blocked.json'
    with open(list_file, 'w') as handle:
        json.dump(blocked, handle)
    monkeypatch.setattr(blocklist, 'MALICIOUS_LIST_FILE', list_file)
    response = upload(intake_client, crx3(archive()))
    assert response.status_code == 422
    assert 'blocklist' in response.json()['detail']


def test_upload_size_limit(artifact_tree, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setenv('CWS_INTAKE_DIR', str(tmp_path / 'intake'))
    monkeypatch.setenv('CWS_INTAKE_MAX_BYTES', '1024')
    client = _make_store_client(monkeypatch, artifact_tree)
    response = upload(client, crx3(archive()) + b'x' * 2048)
    assert response.status_code == 413


def test_list_and_delete(intake_client):
    upload(intake_client, crx3(archive()))
    upload(intake_client, crx3(archive(version='3.0')))
    listing = intake_client.get('/api/admin/intake').json()
    assert listing['configured'] is True
    assert {entry['version'] for entry in listing['uploads']} == {'2.1', '3.0'}
    response = intake_client.delete(f"/api/admin/intake/{key_id()}/2.1")
    assert response.status_code == 200
    listing = intake_client.get('/api/admin/intake').json()
    assert [entry['version'] for entry in listing['uploads']] == ['3.0']
    assert intake_client.delete(f"/api/admin/intake/{key_id()}/2.1").status_code == 404
    assert intake_client.delete('/api/admin/intake/notanid/2.1').status_code == 404


def test_intake_unconfigured(store_client):
    assert store_client.post('/api/admin/intake/upload', content=b'x',
                             headers={'Content-Type': 'application/octet-stream'}).status_code == 503
    assert store_client.get('/api/admin/intake').json() == {'configured': False, 'uploads': []}


def test_all_intake_routes_require_backend_assertions(intake_client):
    from fastapi.testclient import TestClient
    from app.main import app
    raw = TestClient(app)
    for method, path in [('GET', '/api/admin/intake'),
                         ('POST', '/api/admin/intake/upload'),
                         ('DELETE', f'/api/admin/intake/{key_id()}/2.1')]:
        assert raw.request(method, path).status_code == 403


def test_upload_ignores_client_filename(intake_client, tmp_path):
    response = intake_client.post('/api/admin/intake/upload', content=crx3(archive()),
        headers={'Content-Type': 'application/octet-stream',
                 'Content-Disposition': 'attachment; filename="../../outside.crx"'})
    assert response.status_code == 200
    assert response.json()['staged']['filename'].startswith(key_id() + '_')
    assert not (tmp_path / 'outside.crx').exists()


@pytest.mark.parametrize('version', ['65536', '1.99999'])
def test_upload_version_component_range(intake_client, version):
    assert upload(intake_client, crx3(archive(version=version))).status_code == 422
