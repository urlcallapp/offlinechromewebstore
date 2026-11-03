"""Central login edge. Run as one worker, separately from the offline store."""
from collections import OrderedDict
import html
import secrets
import time

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from app.admin_access import assertion
from app.access_paths import machine_request
from auth_gateway.config import settings, read_secret
from auth_gateway.ldap_auth import authenticate

MAX_SESSIONS = 2000
SESSION_TTL = 900
COOKIE = '__Host-cws-session'
HOP = {'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'cookie',
       'authorization', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto'}


def create_app():
    cfg, key = settings()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    sessions = OrderedDict()
    attempts = OrderedDict()
    oauth = OAuth()
    if cfg.get('oidc'):
        oc = cfg['oidc']
        oauth.register('sso', client_id=oc['client_id'], client_secret=read_secret('CWS_OIDC_CLIENT_SECRET'),
                       server_metadata_url=oc['issuer'].rstrip('/') + '/.well-known/openid-configuration',
                       client_kwargs={'scope': 'openid profile email groups', 'code_challenge_method': 'S256'},
                       claims_options={'iss': {'essential': True, 'value': oc['issuer']}},
                       id_token_signing_alg_values_supported=['RS256', 'ES256'])

    class Sessions(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            now = time.monotonic()
            for sid in list(sessions):
                if sessions[sid][0] <= now:
                    sessions.pop(sid, None)
            sid = request.cookies.get(COOKIE)
            if sid not in sessions:
                sid = secrets.token_urlsafe(32)
                while len(sessions) >= MAX_SESSIONS:
                    sessions.popitem(last=False)
                sessions[sid] = (now + SESSION_TTL, {})
            request.scope['session'] = sessions[sid][1]
            request.state.sid = sid
            response = await call_next(request)
            replacement = getattr(request.state, 'new_sid', sid)
            response.set_cookie(COOKIE, replacement, secure=True, httponly=True, samesite='lax',
                                max_age=SESSION_TTL, path='/')
            if request.url.path.startswith('/auth/'):
                response.headers['Cache-Control'] = 'no-store'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['Referrer-Policy'] = 'no-referrer'
                response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            return response
    app.add_middleware(Sessions)

    def logged_in(request, subject, admin):
        sessions.pop(request.state.sid, None)
        sid = secrets.token_urlsafe(32)
        sessions[sid] = (time.monotonic() + SESSION_TTL, {'subject': subject, 'admin': admin, 'csrf': secrets.token_urlsafe(32)})
        request.state.new_sid = sid
        return RedirectResponse('/admin' if admin else '/', status_code=303)

    def csrf_ok(request, value):
        return (request.headers.get('origin') == cfg['origin'] and isinstance(value, str) and
                secrets.compare_digest(value, request.session.get('csrf', 'invalid')))

    @app.get('/auth/style.css')
    async def style():
        return Response("body{margin:0;background:#f3f5f8;color:#17263b;font:16px/1.5 system-ui,sans-serif}main{max-width:420px;margin:8vh auto;padding:32px;background:white;border:1px solid #d6deea;border-radius:16px}h1{font-size:28px;margin:0 0 20px}h2{font-size:19px;margin-top:28px}label{display:block}input:not([type=hidden]){display:block;box-sizing:border-box;width:100%;padding:10px;margin-top:6px;border:1px solid #8b9bb0;border-radius:6px;font:inherit}button,.sso{display:inline-block;background:#1456b8;color:white;padding:10px 18px;border:0;border-radius:6px;font:inherit;text-decoration:none;cursor:pointer}p{margin:16px 0}small{color:#526176}@media(max-width:520px){main{margin:24px 16px;padding:24px}}", media_type='text/css')

    @app.get('/auth/health')
    async def health():
        return Response(status_code=204)

    @app.get('/auth/login')
    async def login(request: Request):
        csrf = request.session.setdefault('csrf', secrets.token_urlsafe(32))
        body = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Store sign in</title><link rel="stylesheet" href="/auth/style.css"><body><main><h1>Store sign in</h1>'
        if cfg.get('oidc'):
            body += '<p><a class="sso" href="/auth/oidc">Sign in with SSO</a></p>'
        if cfg.get('ldap'):
            body += '<h2>Directory sign in</h2><p><small>For directory administrators with store access.</small></p><form method="post" action="/auth/ldap"><input type="hidden" name="csrf" value="' + html.escape(csrf, quote=True) + '"><p><label>Username <input name="username" required autocomplete="username" maxlength="256"></label></p><p><label>Password <input name="password" type="password" required autocomplete="current-password" maxlength="4096"></label></p><button>Sign in</button></form>'
        return HTMLResponse(body + '<p><a href="/auth/account">Account and sign out</a></p><p>Access is controlled by your organization. Sessions expire after 15 minutes.</p></main></body></html>')

    @app.post('/auth/ldap')
    async def ldap_login(request: Request):
        if not cfg.get('ldap'):
            return Response(status_code=404)
        # Bound raw body before form parsing. No credentials in logs or cookies.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                return Response(status_code=413)
        from urllib.parse import parse_qs
        if request.headers.get('content-type', '').split(';')[0] != 'application/x-www-form-urlencoded':
            return Response(status_code=415)
        fields = parse_qs(body.decode('utf-8', errors='replace'))
        if not csrf_ok(request, fields.get('csrf', [''])[0]):
            return Response(status_code=403)
        # Deliberately use transport address, not client-supplied forwarded headers.
        address = request.client.host if request.client else 'unknown'
        now = time.monotonic()
        for addr in list(attempts):
            if attempts[addr][0] < now - 60:
                attempts.pop(addr, None)
        start, count = attempts.get(address, (now, 0))
        if count >= 5 or len(attempts) >= 2000:
            return Response(status_code=429, headers={'Retry-After': '60'})
        attempts[address] = (start, count + 1)
        try:
            dn = await run_in_threadpool(authenticate, cfg['ldap'], fields.get('username', [''])[0], fields.get('password', [''])[0])
        except Exception:
            dn = None
        if not dn:
            return JSONResponse({'error': 'Sign in denied'}, status_code=401)
        return logged_in(request, dn, True)

    @app.get('/auth/oidc')
    async def sso(request: Request):
        if not cfg.get('oidc'):
            return Response(status_code=404)
        try:
            from urllib.parse import urlsplit
            metadata = await oauth.sso.load_server_metadata()
            if metadata.get('issuer') != cfg['oidc']['issuer']:
                raise ValueError('Wrong discovery issuer')
            for endpoint in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
                parsed = urlsplit(metadata[endpoint])
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username:
                    raise ValueError('OIDC endpoints require HTTPS')
            return await oauth.sso.authorize_redirect(request, cfg['origin'] + '/auth/callback', nonce=secrets.token_urlsafe(32))
        except Exception:
            return JSONResponse({'error': 'SSO unavailable'}, status_code=503)

    @app.get('/auth/callback')
    async def callback(request: Request):
        if not cfg.get('oidc'):
            return Response(status_code=404)
        try:
            metadata = await oauth.sso.load_server_metadata()
            if metadata.get('issuer') != cfg['oidc']['issuer']:
                raise ValueError('Wrong discovery issuer')
            algorithms = metadata.get('id_token_signing_alg_values_supported', ['RS256'])
            metadata['id_token_signing_alg_values_supported'] = [a for a in algorithms if a in {'RS256', 'ES256'}]
            if not metadata['id_token_signing_alg_values_supported']:
                raise ValueError('No permitted signing algorithm')
            token = await oauth.sso.authorize_access_token(request, claims_options={'iss': {'essential': True, 'value': cfg['oidc']['issuer']}}, leeway=30)
            if not token.get('id_token'):
                raise ValueError('Signed ID token required')
            claims = token['userinfo']
            if not claims.get('sub') or claims.get('iss') != cfg['oidc']['issuer']:
                raise ValueError('Invalid identity')
            groups = claims.get(cfg['oidc'].get('groups_claim', 'groups'), [])
            if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
                raise ValueError('Invalid groups')
            allowed = cfg['oidc'].get('user_groups', [])
            if allowed and not set(groups).intersection(allowed):
                return Response(status_code=403)
            return logged_in(request, claims['sub'], bool(set(groups).intersection(cfg['oidc']['admin_groups'])))
        except Exception:
            return JSONResponse({'error': 'SSO sign in denied'}, status_code=401)

    @app.get('/auth/session')
    async def session(request: Request):
        if not request.session.get('subject'):
            return Response(status_code=401)
        return JSONResponse({'admin': request.session.get('admin', False), 'csrf': request.session['csrf']})

    @app.get('/auth/account')
    async def account(request: Request):
        if not request.session.get('subject'):
            return RedirectResponse('/auth/login', status_code=303)
        csrf = html.escape(request.session['csrf'], quote=True)
        role = 'Administrator' if request.session.get('admin') else 'Store user'
        return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Store account</title><link rel="stylesheet" href="/auth/style.css"><main><h1>Store account</h1><p>' + role + '</p><p><a href="/">Open store</a></p><form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="' + csrf + '"><button>Sign out</button></form></main></html>')

    @app.post('/auth/logout')
    async def logout(request: Request):
        token = request.headers.get('x-csrf-token', '')
        if not token:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    return Response(status_code=413)
            from urllib.parse import parse_qs
            token = parse_qs(body.decode('utf-8', errors='replace')).get('csrf', [''])[0]
        if not csrf_ok(request, token):
            return Response(status_code=403)
        sessions.pop(request.state.sid, None)
        return Response(status_code=204)

    @app.api_route('/{path:path}', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    async def proxy(request: Request, path: str):
        if request.url.path.startswith('/auth/'):
            return Response(status_code=404)
        admin = request.url.path == '/admin' or request.url.path.startswith('/admin/') or request.url.path == '/api/admin' or request.url.path.startswith('/api/admin/')
        if admin and not request.session.get('admin'):
            if request.session.get('subject'):
                return Response(status_code=403)
            return JSONResponse({'error': 'Sign in required'}, status_code=401) if path.startswith('api/') else RedirectResponse('/auth/login', status_code=303)
        if cfg.get('access', 'anonymous') == 'users-only' and not machine_request(request.method, request.url.path) and not request.session.get('subject'):
            return JSONResponse({'error': 'Sign in required'}, status_code=401) if not (request.method == 'GET' and request.url.path in {'/', '/classic'}) else RedirectResponse('/auth/login', status_code=303)
        if request.method not in {'GET', 'HEAD'}:
            if not (request.url.path in {'/crx', '/crx/'} and request.method == 'POST') and (not admin or request.headers.get('origin') != cfg['origin']):
                return Response(status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 128 * 1024:
                return Response(status_code=413)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP and not k.lower().startswith('x-')}
        headers['X-CWS-Admin-Assertion'] = assertion(key, request.method, request.url.path)
        from urllib.parse import urlsplit
        headers['Host'] = urlsplit(cfg['origin']).netloc
        client = httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False)
        # Fixed origin, encoded path only: never let // or an absolute URL pick a host.
        from urllib.parse import quote
        url = cfg['upstream'].rstrip('/') + quote(request.url.path, safe='/')
        if request.url.query:
            url += '?' + request.url.query
        try:
            upstream = await client.send(client.build_request(request.method, url, headers=headers, content=bytes(body)), stream=True)
        except Exception:
            await client.aclose()
            return Response(status_code=502)
        async def chunks():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()
        response_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP and k.lower() != 'set-cookie'}
        if admin or cfg.get('access') == 'users-only':
            response_headers['Cache-Control'] = 'no-store'
        return StreamingResponse(chunks(), status_code=upstream.status_code, headers=response_headers)

    app.state.config = cfg
    app.state.sessions = sessions
    app.state.oauth = oauth
    return app
