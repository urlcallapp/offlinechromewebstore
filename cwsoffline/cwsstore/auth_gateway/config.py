"""Explicit deployment configuration. Secrets are mounted files, not values."""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def read_secret(name):
    value = Path(os.environ[name + '_FILE']).read_text().strip()
    if len(value) < 1:
        raise ValueError('Empty secret file: ' + name)
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
        read_secret('CWS_OIDC_CLIENT_SECRET')
    key = read_secret('CWS_ADMIN_GATEWAY_SECRET')
    if len(key) < 32:
        raise ValueError('Gateway signing secret must be at least 32 characters')
    return cfg, key
