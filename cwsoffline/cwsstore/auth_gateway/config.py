"""Explicit deployment configuration. Secrets are mounted files, not values."""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

SESSION_DEFAULTS = {'idle_ttl_seconds': 900, 'max_ttl_seconds': 28800,
                    'refresh_interval_seconds': 300, 'max_stale_seconds': 3600}


def read_secret(name):
    value = Path(os.environ[name + '_FILE']).read_text().strip()
    if len(value) < 1:
        raise ValueError('Empty secret file: ' + name)
    return value


def _bounded_int(source, name, default, low, high):
    value = source.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f'{name} must be an integer between {low} and {high}')
    return value


def settings():
    path = os.environ.get('CWS_AUTH_CONFIG_FILE')
    if not path:
        raise ValueError('CWS_AUTH_CONFIG_FILE is required')
    cfg = json.loads(Path(path).read_text())
    for field in ('access', 'origin', 'upstream'):
        if os.environ.get('CWS_AUTH_' + field.upper()):
            cfg[field] = os.environ['CWS_AUTH_' + field.upper()]
    if cfg.get('access', 'anonymous') not in {'anonymous', 'users-only'}:
        raise ValueError('access must be anonymous or users-only')
    if cfg.get('access') == 'users-only' and not cfg.get('oidc'):
        raise ValueError('users-only browsing requires OIDC')
    origin = urlsplit(cfg['origin'])
    if origin.scheme != 'https' or not origin.netloc or origin.path or origin.query or origin.fragment or origin.username:
        raise ValueError('origin must be an exact HTTPS origin without a path')
    upstream = urlsplit(cfg['upstream'])
    if upstream.scheme not in {'http', 'https'} or not upstream.hostname or upstream.path not in {'', '/'} or upstream.username or upstream.query or upstream.fragment:
        raise ValueError('upstream must be a fixed internal HTTP(S) origin')
    session = cfg.get('session')
    if session is not None:
        if not isinstance(session, dict):
            raise ValueError('session must be an object')
        if session.get('backend', 'memory') != 'memory':
            raise ValueError('Only the server-side memory session backend is supported; '
                             'multi-replica deployments need a shared session store, not client-side tokens')
        _bounded_int(session, 'idle_ttl_seconds', SESSION_DEFAULTS['idle_ttl_seconds'], 60, 86400)
        _bounded_int(session, 'refresh_interval_seconds', SESSION_DEFAULTS['refresh_interval_seconds'], 30, 86400)
        stale = _bounded_int(session, 'max_stale_seconds', SESSION_DEFAULTS['max_stale_seconds'], 60, 86400)
        if stale < session.get('refresh_interval_seconds', SESSION_DEFAULTS['refresh_interval_seconds']):
            raise ValueError('session.max_stale_seconds must not be shorter than the refresh interval')
        if _bounded_int(session, 'max_ttl_seconds', SESSION_DEFAULTS['max_ttl_seconds'], 60, 604800) < session.get('idle_ttl_seconds', 900):
            raise ValueError('session.max_ttl_seconds must not be shorter than the idle TTL')
    if not cfg.get('ldap') and not cfg.get('oidc'):
        raise ValueError('Enable LDAP, OIDC, or both')
    if cfg.get('ldap'):
        ld = cfg['ldap']
        if not ld.get('host') or '://' in ld['host'] or not ld.get('admin_group_dn') or not ld.get('base_dn') or not ld.get('bind_dn'):
            raise ValueError('LDAP host, base_dn, bind_dn and admin_group_dn are required')
        if ld.get('tls', 'ldaps') not in {'ldaps', 'starttls'}:
            raise ValueError('LDAP requires verified LDAPS or StartTLS')
        import re
        if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]*', ld.get('username_attribute', 'uid')):
            raise ValueError('Invalid LDAP username attribute')
        nested = ld.get('nested_groups')
        if nested is not None:
            if not isinstance(nested, dict):
                raise ValueError('ldap.nested_groups must be an object')
            for flag in ('enabled', 'matching_rule_in_chain'):
                if not isinstance(nested.get(flag, False), bool):
                    raise ValueError('ldap.nested_groups.' + flag + ' must be boolean')
            _bounded_int(nested, 'max_depth', 5, 1, 16)
            _bounded_int(nested, 'max_groups', 128, 4, 4096)
            base = nested.get('group_search_base')
            if base is not None and (not isinstance(base, str) or not base.strip()):
                raise ValueError('ldap.nested_groups.group_search_base must be a non-empty DN')
        read_secret('CWS_LDAP_BIND_PASSWORD')
    if cfg.get('oidc'):
        oidc = cfg['oidc']
        issuer = urlsplit(oidc['issuer'])
        if issuer.scheme != 'https' or not issuer.netloc or issuer.query or issuer.fragment or issuer.username:
            raise ValueError('OIDC requires an HTTPS issuer')
        if not oidc.get('client_id') or not isinstance(oidc.get('admin_groups'), list) or not oidc.get('admin_groups') or not all(isinstance(g, str) and g for g in oidc['admin_groups']):
            raise ValueError('OIDC client_id and explicit admin_groups are required')
        if not isinstance(oidc.get('user_groups', []), list) or not all(isinstance(g, str) and g for g in oidc.get('user_groups', [])):
            raise ValueError('OIDC user_groups must be a list of group names')
        if not isinstance(oidc.get('refresh', True), bool):
            raise ValueError('oidc.refresh must be boolean')
        read_secret('CWS_OIDC_CLIENT_SECRET')
    key = read_secret('CWS_ADMIN_GATEWAY_SECRET')
    if len(key) < 32:
        raise ValueError('Gateway signing secret must be at least 32 characters')
    return cfg, key
