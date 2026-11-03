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


def test_windows_and_legacy_export_formats():
    catalog = [{"extension_id": "a" * 32}, {"extension_id": "b" * 32}]
    result = policy.generate_policy({"base_url": "https://store.example.internal", "default_mode": "blocked",
                              "extensions": {"a" * 32: "force_installed", "b" * 32: "allowed"}}, catalog, [])
    assert result["extension_install_forcelist"] == ["a" * 32 + ";https://store.example.internal/crx"]
    assert result["extension_install_sources"] == ["https://store.example.internal/*"]
    registry = result["windows_registry_file"]
    assert registry.startswith("Windows Registry Editor Version 5.00")
    assert "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]" in registry
    assert '\\"installation_mode\\":\\"force_installed\\"' in registry  # JSON stays valid after .reg escaping
    assert registry.count("ExtensionSettings") == 1
    script = result["gpo_powershell_script"]
    assert "Set-GPRegistryValue" in script and "SET-TO-YOUR-EXISTING-GPO-NAME" in script
    assert "-Type String" in script and "3rdparty" not in script
    assert any("overrides the legacy" in warning for warning in result["warnings"])
    # PowerShell single-quote escaping survives apostrophes in values.
    result = policy.generate_policy({"base_url": "https://store.example.internal", "default_mode": "blocked",
                              "blocked_install_message": "it's blocked", "extensions": {"a" * 32: "allowed"}}, catalog, [])
    assert "it''s blocked" in result["gpo_powershell_script"]


def test_export_script_only_merges_into_existing_gpo():
    """The store only writes reviewable files and never runs them. When an admin
    runs the PowerShell script it DOES modify the named GPO (that is its job),
    so the script must be limited to merging values into an existing GPO:
    no GPO creation, deletion or linking, and it refuses to run as exported."""
    catalog = [{"extension_id": "a" * 32}]
    result = policy.generate_policy({"base_url": "https://store.example.internal", "default_mode": "allowed",
                              "extensions": {"a" * 32: "allowed"}}, catalog, [])
    script = result["gpo_powershell_script"]
    for forbidden in ["New-GPO", "Remove-GPO", "New-GPLink", "Set-GPInheritance", "Invoke-GPUpdate /force"]:
        assert forbidden not in script


# Load extension_policy standalone too, like policy above: no store package import.
APP_DIR = Path(CWSSTORE_DIR) / 'app'
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
ext_spec = importlib.util.spec_from_file_location('extension_policy', APP_DIR / 'extension_policy.py')
extension_policy = importlib.util.module_from_spec(ext_spec)
ext_spec.loader.exec_module(extension_policy)
sys.modules.setdefault('extension_policy', extension_policy)

EXT_ID = "b" * 32
SCHEMA = {
    "type": "object",
    "properties": {
        "Server": {"type": "string", "pattern": "^https://"},
        "Retries": {"type": "integer"},
        "Verbose": {"type": "boolean"},
        "Tags": {"type": "array", "items": {"type": "string"}},
        "Mode": {"type": "string", "enum": ["fast", "safe"]},
    },
    "required": ["Server"],
}


def _assets(tmp_path, schema=SCHEMA):
    import json as _json
    extension_dir = tmp_path / "assets" / EXT_ID
    extension_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"name": "Internal tool", "version": "1.0"}
    if schema is not None:
        manifest["storage"] = {"managed_schema": "schema.json"}
        (extension_dir / "schema.json").write_text(_json.dumps(schema))
    (extension_dir / "manifest.json").write_text(_json.dumps(manifest))
    return str(tmp_path / "assets")


def _spec(policies):
    return {"base_url": "https://store.example.internal", "default_mode": "allowed",
            "extensions": {EXT_ID: "allowed"}, "extension_policies": policies}


def _catalog():
    return [{"extension_id": EXT_ID, "name": "Internal tool"}]


def test_managed_policy_happy_path(tmp_path):
    assets = _assets(tmp_path)
    result = policy.generate_policy(_spec({EXT_ID: {"Server": "https://app.internal", "Retries": 3,
                                             "Verbose": True, "Tags": ["a", "b"], "Mode": "fast"}}),
                             _catalog(), [], assets_dir=assets)
    assert result["linux_managed_policy"]["3rdparty"]["extensions"][EXT_ID]["Retries"] == 3
    registry = result["windows_registry_file"]
    assert f"3rdparty\\extensions\\{EXT_ID}\\policy" in registry
    assert '"Server"="https://app.internal"' in registry
    assert '"Retries"=dword:00000003' in registry
    assert '"Verbose"=dword:00000001' in registry
    assert '"Tags"="[\\"a\\",\\"b\\"]"' in registry
    script = result["gpo_powershell_script"]
    assert "3rdparty\\extensions" in script and "-Type DWord -Value 3" in script
    assert result["extension_policy_schemas"][EXT_ID] == "schema.json"


def test_managed_policy_requires_declared_schema(tmp_path):
    assets = _assets(tmp_path, schema=None)
    with pytest.raises(ValueError, match="declares no storage.managed_schema"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x"}}), _catalog(), [], assets_dir=assets)


def test_managed_policy_type_and_required_enforced(tmp_path):
    assets = _assets(tmp_path)
    with pytest.raises(ValueError, match="expected integer"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x", "Retries": "three"}}), _catalog(), [], assets_dir=assets)
    with pytest.raises(ValueError, match="missing required key"):
        policy.generate_policy(_spec({EXT_ID: {"Retries": 1}}), _catalog(), [], assets_dir=assets)
    with pytest.raises(ValueError, match="enum"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x", "Mode": "slow"}}), _catalog(), [], assets_dir=assets)


def test_managed_policy_undeclared_key_rejected_when_closed(tmp_path):
    schema = dict(SCHEMA, additionalProperties=False)
    assets = _assets(tmp_path, schema=schema)
    with pytest.raises(ValueError, match="not declared"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x", "Surprise": 1}}), _catalog(), [], assets_dir=assets)
    # Chrome policy names must be declared even without additionalProperties.
    assets = _assets(tmp_path)
    with pytest.raises(ValueError, match="not declared"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x", "Surprise": 1}}), _catalog(), [], assets_dir=assets)


def test_managed_policy_unenforced_keywords_warn(tmp_path):
    assets = _assets(tmp_path)
    result = policy.generate_policy(_spec({EXT_ID: {"Server": "ftp://not-checked"}}), _catalog(), [], assets_dir=assets)
    assert any("pattern" in warning and "does not enforce" in warning for warning in result["warnings"])


def test_managed_policy_requires_assets_and_clean_extension(tmp_path):
    with pytest.raises(ValueError, match="assets directory"):
        policy.generate_policy(_spec({EXT_ID: {"Server": "x"}}), _catalog(), [])
    assets = _assets(tmp_path)
    blocked_spec = _spec({EXT_ID: {"Server": "x"}})
    blocked_spec["extensions"] = {EXT_ID: "blocked"}
    with pytest.raises(ValueError, match="blocklisted"):
        policy.generate_policy(blocked_spec, _catalog(), [EXT_ID], assets_dir=assets)
    missing_spec = _spec({EXT_ID: {"Server": "x"}})
    missing_spec["extensions"] = {EXT_ID: "blocked"}
    with pytest.raises(ValueError, match="not in the local catalog"):
        policy.generate_policy(missing_spec, [], [], assets_dir=assets)


def test_admin_javascript_syntax_and_scoped_selectors():
    import shutil
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is checked by the CI frontend job')
    html = (Path(CWSSTORE_DIR) / 'app/templates/admin.html').read_text()
    js = html.split('<script>', 1)[1].split('</script>', 1)[0]
    subprocess.run([node, '--check'], input=js, text=True, check=True, capture_output=True)
    assert "select[data-id]" in js
    assert 'for(const format of Object.keys(downloads))' in js


def test_managed_schema_uses_actual_nested_manifest_key(tmp_path):
    assets = _assets(tmp_path)
    manifest_path = Path(assets) / EXT_ID / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    assert manifest['storage']['managed_schema'] == 'schema.json'
    manifest.pop('storage')
    manifest['storage.managed_schema'] = 'schema.json'  # wrong flat spelling
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='declares no'):
        policy.generate_policy(_spec({EXT_ID: {'Server': 'x'}}), _catalog(), [], assets_dir=assets)
