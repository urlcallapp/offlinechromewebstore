"""Authentication boundary and central-login tests, without external services."""
import importlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from conftest import CWSSTORE_DIR


def test_store_default_admin_is_closed(store_client, built_index, monkeypatch):
    monkeypatch.delenv('CWS_ADMIN_GATEWAY_SECRET_FILE')
    assert store_client.get('/admin').status_code == 503
    assert store_client.post('/api/admin/policy/export', json={}).status_code == 503
    assert store_client.get('/json').status_code == 200


def test_store_rejects_unsigned_forged_and_wrong_operation(store_client):
    from app.main import app
    from app.admin_access import assertion, secret
    raw = TestClient(app)
    for headers in [{}, {'X-User': 'admin', 'X-Groups': 'admins'}, {'X-CWS-Admin-Assertion': 'forged'},
                    {'X-CWS-Admin-Assertion': assertion(secret(), 'POST', '/admin')}]:
        assert raw.get('/admin', headers=headers).status_code == 403
        assert raw.post('/api/admin/policy/export', headers=headers, json={}).status_code == 403


def test_users_only_guards_all_backend_bytes(store_client, built_index, monkeypatch):
    from app.main import app
    raw = TestClient(app)
    monkeypatch.setenv('CWS_STORE_ACCESS', 'users-only')
    for path in ['/', '/json', '/download/test', '/artifacts/test', '/static/app/index.html', '/docs']:
        assert raw.get(path).status_code == 403
    assert store_client.get('/json').status_code == 200
    monkeypatch.setenv('CWS_STORE_ACCESS', 'typo')
    assert raw.get('/json').status_code == 503


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(CWSSTORE_DIR)
    key = tmp_path / 'key'; key.write_text('test-only-long-secret-' * 3)
    password = tmp_path / 'password'; password.write_text('test-service-bind-password')
    conf = {'origin': 'https://store.test', 'upstream': 'http://127.0.0.1:8005', 'access': 'anonymous',
            'ldap': {'host': 'directory.test', 'base_dn': 'dc=test', 'bind_dn': 'cn=search,dc=test', 'admin_group_dn': 'cn=admins,dc=test'},
            'oidc': {'issuer': 'https://idp.test', 'client_id': 'store', 'admin_groups': ['admins']}}
    path = tmp_path / 'config.json';path.write_text(json.dumps(conf))
    monkeypatch.setenv('CWS_AUTH_CONFIG_FILE', str(path))
    monkeypatch.setenv('CWS_ADMIN_GATEWAY_SECRET_FILE', str(key))
    monkeypatch.setenv('CWS_LDAP_BIND_PASSWORD_FILE', str(password))
    monkeypatch.setenv('CWS_OIDC_CLIENT_SECRET_FILE', str(password))
    from auth_gateway.main import create_app
    app = create_app()
    return TestClient(app, base_url='https://store.test'), app, conf, path


def ldap_signin(client, username='alice', password='test-user-password', origin='https://store.test'):
    import re
    text = client.get('/auth/login').text
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    return client.post('/auth/ldap', data={'username': username, 'password': password, 'csrf': csrf},
                       headers={'Origin': origin}, follow_redirects=False)


def test_gateway_login_page_and_denials(gateway):
    client, app, _, _ = gateway
    response = client.get('/auth/login')
    assert 'Sign in with SSO' in response.text and 'Directory sign in' in response.text
    assert 'HttpOnly' in response.headers['set-cookie'] and 'Secure' in response.headers['set-cookie']
    assert client.get('/admin', follow_redirects=False).status_code == 303
    assert client.post('/api/admin/policy/export').status_code == 401
    assert client.post('/auth/ldap', data={'username':'alice', 'password':'wrong'}).status_code == 403
    assert client.post('/auth/logout').status_code == 403
    with patch('auth_gateway.main.authenticate', return_value=None):
        assert ldap_signin(client).status_code == 401
    with patch('auth_gateway.main.authenticate', return_value='uid=alice,dc=test'):
        response=ldap_signin(client)
        assert response.status_code == 303
        assert client.get('/auth/session').json()['admin'] is True
        csrf=client.get('/auth/session').json()['csrf']
        assert client.post('/auth/logout',headers={'Origin':'https://store.test','X-CSRF-Token':csrf}).status_code == 204
        assert client.get('/auth/session').status_code == 401


def test_rate_limit_and_backend_failure(gateway):
    client, _, _, _ = gateway
    with patch('auth_gateway.main.authenticate', return_value=None):
        for _ in range(5):assert ldap_signin(client).status_code == 401
        assert ldap_signin(client).status_code == 429
    with patch('httpx.AsyncClient.send', side_effect=RuntimeError('down')):
        assert client.get('/json').status_code == 502


def test_gateway_strict_mode_and_nonadmin(gateway):
    client, app, cfg, _ = gateway
    app.state.config['access']='users-only'
    for path in ['/json','/download/test','/artifacts/test','/static/app/index.html']:
        assert client.get(path).status_code == 401
    client.get('/auth/login')
    for _, data in app.state.sessions.values(): data.update(subject='regular-user', admin=False)
    assert client.get('/admin').status_code == 403
    assert client.post('/api/admin/policy/export',headers={'Origin':'https://store.test'}).status_code == 403


def test_oidc_start_and_callback_fail_closed(gateway):
    client, app, _, _ = gateway
    with patch.object(app.state.oauth.sso, 'authorize_redirect', side_effect=RuntimeError('down')):
        assert client.get('/auth/oidc').status_code == 503
    assert client.get('/auth/callback?code=untrusted&state=forged').status_code == 401


@pytest.mark.parametrize('claims,status,admin', [
    ({'sub':'alice','iss':'https://idp.test','groups':['admins']},303,True),
    ({'sub':'bob','iss':'https://idp.test','groups':['staff']},303,False),
    ({'sub':'alice','iss':'https://evil.test','groups':['admins']},401,None),
    ({'sub':'alice','iss':'https://idp.test','groups':'admins'},401,None)])
def test_verified_oidc_claim_authorization(gateway, claims, status, admin):
    client, app, _, _ = gateway
    # Authlib's signed-token validation is tested separately; only verified claims enter here.
    from unittest.mock import AsyncMock
    with patch.object(app.state.oauth.sso,'load_server_metadata',AsyncMock(return_value={'issuer':'https://idp.test'})), patch.object(app.state.oauth.sso,'authorize_access_token',AsyncMock(return_value={'id_token':'verified-by-library', 'userinfo':claims})):
        assert client.get('/auth/callback',follow_redirects=False).status_code == status
    if admin is not None:assert client.get('/auth/session').json()['admin'] is admin


@pytest.mark.parametrize('change', [{'access':'typo'}, {'origin':'http://store.test'}, {'access':'users-only','oidc':None},
                                  {'ldap':{'host':'ldap.test','base_dn':'dc=test','bind_dn':'search','admin_group_dn':'admins','tls':'plain'}}])
def test_bad_config_refused(gateway, change):
    _, _, cfg, path=gateway
    cfg.update(change);path.write_text(json.dumps(cfg))
    from auth_gateway.main import create_app
    with pytest.raises((ValueError,KeyError)):create_app()


def test_ldap_empty_password_and_filter_escaping(gateway):
    _, _, cfg, _=gateway
    from auth_gateway.ldap_auth import authenticate
    assert authenticate(cfg['ldap'],'alice','') is None
    assert authenticate(cfg['ldap'],'','password') is None
    from unittest.mock import MagicMock
    service=MagicMock(); service.entries=[]
    with patch('auth_gateway.ldap_auth.Server') as server, patch('auth_gateway.ldap_auth.Connection') as connection:
        connection.return_value.__enter__.return_value=service
        assert authenticate(cfg['ldap'],'*)(uid=*)','password') is None
        args=service.search.call_args.args
        assert args[1] == '(uid=\\2a\\29\\28uid=\\2a\\29)'
        assert server.call_args.kwargs['tls'].validate == __import__('ssl').CERT_REQUIRED
        assert connection.call_args.kwargs['auto_referrals'] is False


def test_public_machine_routes_preserve_updates_without_login(store_client, built_index, monkeypatch):
    from app.main import app
    from conftest import TAMPERMONKEY_ID
    raw=TestClient(app)
    monkeypatch.setenv('CWS_STORE_ACCESS','users-only')
    entries=store_client.get('/json').json()
    entry=next(e for e in entries if e['extension_id']==TAMPERMONKEY_ID)
    assert raw.get('/crx').status_code == 200
    assert raw.post('/crx',content='<request><app appid="'+TAMPERMONKEY_ID+'"/></request>').status_code == 200
    assert raw.get('/download/'+TAMPERMONKEY_ID).status_code == 200
    assert raw.get('/'+entry['versions'][0]['path_url']).status_code == 200
    for path in ['/artifacts/extensions_info.json','/artifacts/malicious_extensions.json','/assets/test','/api/admin/policy/export','/api/extensions/'+TAMPERMONKEY_ID]:
        assert raw.get(path).status_code == 403
    monkeypatch.setenv('CWS_PUBLIC_ORIGIN','https://extensions.test')
    assert 'codebase="https://extensions.test/artifacts/' in raw.get('/crx').text


def test_ldap_tls_bind_success_and_no_plaintext_fallback(gateway):
    _, _, cfg, _=gateway
    from auth_gateway.ldap_auth import authenticate
    from unittest.mock import MagicMock
    entry=MagicMock();entry.entry_dn='uid=alice,dc=test';entry.entry_attributes_as_dict={'memberOf':['cn=admins,dc=test']}
    service=MagicMock();service.entries=[entry]
    user=MagicMock();user.bound=True
    with patch('auth_gateway.ldap_auth.Connection') as conn, patch('auth_gateway.ldap_auth.Server'):
        conn.side_effect=[MagicMock(__enter__=lambda s:service),MagicMock(__enter__=lambda s:user)]
        assert authenticate(cfg['ldap'],'alice','test-password')=='uid=alice,dc=test'
        assert conn.call_args.args[1:] == ('uid=alice,dc=test','test-password')
    cfg['ldap']['tls']='starttls'
    from ldap3 import AUTO_BIND_TLS_BEFORE_BIND
    with patch('auth_gateway.ldap_auth.Connection',side_effect=RuntimeError('TLS failed')) as conn, patch('auth_gateway.ldap_auth.Server'):
        with pytest.raises(RuntimeError):authenticate(cfg['ldap'],'alice','test-password')
        assert conn.call_count==1
        assert conn.call_args.kwargs['auto_bind']==AUTO_BIND_TLS_BEFORE_BIND


def test_signed_oidc_tokens_are_validated(gateway):
    import asyncio,time
    from authlib.jose import JsonWebKey,jwt
    _,app,_,_=gateway
    key=JsonWebKey.generate_key('RSA',2048,{'kid':'test-key'},is_private=True)
    oidc=app.state.oauth.sso
    oidc.server_metadata.update(issuer='https://idp.test',jwks={'keys':[key.as_dict(is_private=False)]},id_token_signing_alg_values_supported=['RS256'])
    # Supply local JWKS, no network allowed in token validation tests.
    from unittest.mock import AsyncMock
    now=int(time.time())
    base={'iss':'https://idp.test','sub':'alice','aud':'store','iat':now,'exp':now+120,'nonce':'expected'}
    async def parse(claims, signing_key=key):
        token={'id_token':jwt.encode({'alg':'RS256','kid':'test-key'},claims,signing_key).decode()}
        with patch.object(oidc,'load_server_metadata',AsyncMock(return_value=oidc.server_metadata)), patch.object(oidc,'fetch_jwk_set',AsyncMock(return_value={'keys':[key.as_dict(is_private=False)]})):
            return await oidc.parse_id_token(token,nonce='expected',claims_options={'iss':{'essential':True,'value':'https://idp.test'}},leeway=0)
    assert asyncio.run(parse(base))['sub']=='alice'
    for change in [{'iss':'https://evil.test'},{'aud':'other-client'},{'exp':now-60},{'nonce':'forged'}]:
        with pytest.raises(Exception):asyncio.run(parse(dict(base,**change)))
    other=JsonWebKey.generate_key('RSA',2048,{'kid':'test-key'},is_private=True)
    with pytest.raises(Exception):asyncio.run(parse(base,other))


def test_expired_and_wrong_path_gateway_assertions(store_client):
    from app.admin_access import assertion,secret
    from app.main import app
    raw=TestClient(app)
    with patch('itsdangerous.timed.time.time',return_value=1):expired=assertion(secret(),'GET','/admin')
    assert raw.get('/admin',headers={'X-CWS-Admin-Assertion':expired}).status_code==403
    wrong=assertion(secret(),'GET','/json')
    assert raw.get('/admin',headers={'X-CWS-Admin-Assertion':wrong}).status_code==403


def test_machine_path_classification():
    from app.access_paths import machine_request
    valid='/artifacts/extensions/'+'a'*32+'/1.0/Internal Tool.crx'
    assert machine_request('GET',valid)
    assert machine_request('POST','/crx')
    for path in ['/api/admin/policy/export','/admin','/crx/other','//crx',valid.replace('1.0','..'),valid.replace('Internal Tool.crx','file.json'),'/artifacts/extensions_info.json']:
        assert not machine_request('GET',path)
    assert not machine_request('POST',valid)


def test_gateway_streaming_strip_headers_and_backend_signature(gateway, monkeypatch):
    import httpx,asyncio
    client,app,_,_=gateway
    seen=[]
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):yield b'original-crx-bytes'
    async def send(self,request,**kwargs):
        seen.append(request)
        return httpx.Response(200,headers={'Content-Type':'application/octet-stream'},stream=Stream())
    with patch('httpx.AsyncClient.send',send):
        response=client.post('/crx',content='<request/>',headers={'X-User':'admin','X-CWS-Admin-Assertion':'forged','Authorization':'Bearer secret'})
        assert response.status_code==200 and response.content==b'original-crx-bytes'
        assert seen[0].url.host=='127.0.0.1'
        assert 'x-user' not in seen[0].headers and 'authorization' not in seen[0].headers
        assert seen[0].headers['x-cws-admin-assertion']!='forged'
        assert seen[0].headers['host']=='store.test'
        assert client.post('/api/admin/policy/export',json={}).status_code==401
        with patch('auth_gateway.main.authenticate',return_value='uid=alice,dc=test'):
            assert ldap_signin(client).status_code==303
        assert client.post('/api/admin/policy/export',json={},headers={'Origin':'https://evil.test'}).status_code==403
        assert client.post('/api/admin/policy/export',json={},headers={'Origin':'https://store.test'}).status_code==200


def test_oidc_flow_state_nonce_pkce_and_replay(gateway):
    import time
    from urllib.parse import urlsplit,parse_qs
    from authlib.jose import JsonWebKey,jwt
    from unittest.mock import AsyncMock
    client,app,_,_=gateway
    oc=app.state.oauth.sso
    key=JsonWebKey.generate_key('RSA',2048,{'kid':'test'},is_private=True)
    metadata={'issuer':'https://idp.test','authorization_endpoint':'https://idp.test/auth','token_endpoint':'https://idp.test/token',
              'jwks_uri':'https://idp.test/keys','id_token_signing_alg_values_supported':['RS256']}
    with patch.object(oc,'load_server_metadata',AsyncMock(return_value=metadata)):
        start=client.get('/auth/oidc',follow_redirects=False)
        assert start.status_code==302
        query=parse_qs(urlsplit(start.headers['location']).query)
        assert query['redirect_uri']==['https://store.test/auth/callback']
        assert query['code_challenge_method']==['S256'] and query['nonce']
        now=int(time.time())
        token=jwt.encode({'alg':'RS256','kid':'test'},{'iss':'https://idp.test','aud':'store','sub':'alice','iat':now,'exp':now+120,'nonce':query['nonce'][0],'groups':['admins']},key).decode()
        with patch.object(oc,'fetch_access_token',AsyncMock(return_value={'id_token':token})), patch.object(oc,'fetch_jwk_set',AsyncMock(return_value={'keys':[key.as_dict(is_private=False)]})):
            response=client.get('/auth/callback',params={'state':query['state'][0],'code':'valid-code'},follow_redirects=False)
            assert response.status_code==303
            assert client.get('/auth/session').json()['admin'] is True
            assert client.get('/auth/callback',params={'state':query['state'][0],'code':'valid-code'}).status_code==401


def test_oidc_unsigned_userinfo_not_accepted(gateway):
    from unittest.mock import AsyncMock
    client,app,_,_=gateway
    oc=app.state.oauth.sso
    with patch.object(oc,'load_server_metadata',AsyncMock(return_value={'issuer':'https://idp.test'})), patch.object(oc,'authorize_access_token',AsyncMock(return_value={'userinfo':{'sub':'injected','iss':'https://idp.test','groups':['admins']}})):
        assert client.get('/auth/callback').status_code==401
        assert client.get('/auth/session').status_code==401


def test_gateway_factory_runs_in_fresh_process(gateway):
    import subprocess,socket,time
    _,_,_,_=gateway
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    command=[sys.executable,'-m','uvicorn','auth_gateway.main:create_app','--factory','--host','127.0.0.1','--port',str(port),'--no-access-log','--no-proxy-headers']
    process=subprocess.Popen(command,cwd=CWSSTORE_DIR,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    import httpx
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise AssertionError(process.communicate()[1].decode())
            try:
                response=httpx.get(f'http://127.0.0.1:{port}/auth/health',timeout=.2)
                if response.status_code==204:break
            except httpx.TransportError:time.sleep(.05)
        else:raise AssertionError('Gateway did not become ready')
        response=httpx.get(f'http://127.0.0.1:{port}/auth/login')
        assert response.status_code==200 and 'Sign in with SSO' in response.text
        assert httpx.get(f'http://127.0.0.1:{port}/api/admin/policy/export').status_code==401
    finally:
        process.terminate();process.communicate(timeout=5)
