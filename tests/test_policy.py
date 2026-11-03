"""Policy exports are local, explicit, blocklist-aware and do not mutate devices."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from conftest import CWSSTORE_DIR, TAMPERMONKEY_ID as FIRST, TRANSLATE_ID as SECOND

spec = importlib.util.spec_from_file_location('offline_policy', Path(CWSSTORE_DIR) / 'app/policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def selection(**changes):
    return dict(base_url='https://extensions.example.internal', default_mode='blocked',
                extensions={FIRST: 'force_installed', SECOND: 'allowed'}, **changes)


def test_policy_shapes_and_offline_update_override():
    data = policy.generate_policy(selection(), [{'extension_id': FIRST}, {'extension_id': SECOND}])
    settings = data['extension_settings']
    assert settings['*'] == {'installation_mode': 'blocked'}
    assert settings[FIRST] == {'installation_mode': 'force_installed', 'update_url': 'https://extensions.example.internal/crx', 'override_update_url': True}
    assert settings[SECOND] == {'installation_mode': 'allowed'}
    assert json.loads(data['gpo_extension_settings']) == settings
    assert '\n' not in data['gpo_extension_settings']
    assert data['linux_managed_policy'] == {'ExtensionSettings': settings}
    assert data['extension_allowlist'] == sorted([FIRST, SECOND])
    assert 'clients2.google.com' not in json.dumps(settings)


@pytest.mark.parametrize('origin', ['http://localhost:8005', 'http://0.0.0.0', 'ftp://store', 'https://user:secret@store', 'https://store/prefix', 'https://store?x=1', 'https://store#x', 'https://store\\evil', 'https://store:bad', 'https://store\n.evil', 'http://127.2.3.4', 'http://224.0.0.1', 'https://bad..host', 'https://-bad.host'])
def test_invalid_origins(origin):
    data = selection(); data['base_url'] = origin
    with pytest.raises(ValueError): policy.generate_policy(data, [{'extension_id': FIRST}, {'extension_id': SECOND}])


@pytest.mark.parametrize('mode', ['removed', '*', '', 'force', None, [], {}])
def test_invalid_modes(mode):
    data = selection();data['extensions'] = {FIRST: mode}
    with pytest.raises(ValueError): policy.generate_policy(data, [{'extension_id': FIRST}])


def test_default_and_selection_must_be_explicit():
    for field in ['default_mode', 'extensions', 'base_url']:
        data = selection();data.pop(field)
        with pytest.raises(ValueError): policy.generate_policy(data, [])


def test_blocked_or_unavailable_cannot_be_allowed():
    with pytest.raises(ValueError): policy.generate_policy(selection(), [{'extension_id': FIRST}])
    with pytest.raises(ValueError): policy.generate_policy(selection(), [{'extension_id': FIRST}, {'extension_id': SECOND}], [FIRST])
    data=selection(); data['extensions']={SECOND:'normal_installed'};data['default_mode']='allowed'
    result=policy.generate_policy(data,[{'extension_id': SECOND}],[FIRST])
    assert result['extension_settings'][FIRST] == {'installation_mode':'blocked'}
    assert result['extension_settings'][SECOND]['override_update_url'] is True
    with pytest.raises(ValueError): policy.generate_policy(data, [], ['not-an-id'])


def test_export_api_and_admin(store_client, built_index):
    assert store_client.get('/admin').status_code == 200
    response=store_client.post('/api/admin/policy/export',json=selection())
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json()['extension_settings'][FIRST]['override_update_url'] is True
    assert store_client.post('/api/admin/policy/export',content='not-json').status_code == 422
    assert store_client.post('/api/admin/policy/export',content='x'*(128*1024+1)).status_code == 413


def test_export_refuses_stale_blocked_or_missing_crx(blocked_store_client, artifact_tree):
    assert FIRST not in blocked_store_client.get('/admin').text
    assert blocked_store_client.post('/api/admin/policy/export',json=selection()).status_code == 422
    data=selection();data['extensions']={SECOND:'allowed'}
    result=blocked_store_client.post('/api/admin/policy/export',json=data).json()
    assert result['extension_settings'][FIRST]['installation_mode'] == 'blocked'
    for path in (Path(artifact_tree['artifacts'])/'extensions'/SECOND).rglob('*.crx'):path.unlink()
    assert blocked_store_client.post('/api/admin/policy/export',json=data).status_code == 422


def test_corrupt_blocklist_refuses_export(store_client,built_index,artifact_tree):
    (Path(artifact_tree['artifacts'])/'malicious_extensions.json').write_text('invalid')
    assert store_client.post('/api/admin/policy/export',json=selection()).status_code == 422


def test_cli_offline_no_store_imports(tmp_path):
    paths=[]
    for name,data in [('spec',selection()),('catalog',[{'extension_id':FIRST},{'extension_id':SECOND}]),('blocklist',[])]:
        path=tmp_path/(name+'.json');path.write_text(json.dumps(data));paths.extend(['--'+name,str(path)])
    command=[sys.executable,str(Path(CWSSTORE_DIR)/'app/policy.py'),*paths]
    result=subprocess.run(command+['--format','gpo'],capture_output=True,text=True,check=True)
    assert json.loads(result.stdout)[FIRST]['override_update_url'] is True
    assert len(result.stdout.splitlines()) == 1
    result=subprocess.run(command+['--format','linux'],capture_output=True,text=True,check=True)
    assert 'ExtensionSettings' in json.loads(result.stdout)
