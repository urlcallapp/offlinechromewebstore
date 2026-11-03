"""Read-only service search, verified TLS, user bind, direct group membership."""
import ssl
from ldap3 import Server, Connection, Tls, SUBTREE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.utils.conv import escape_filter_chars
from auth_gateway.config import read_secret


def authenticate(cfg, username, password):
    if not username or len(username) > 256 or not password or len(password) > 4096 or '\x00' in username or '\x00' in password:
        return None
    server = Server(cfg['host'], port=cfg.get('port', 636 if cfg.get('tls', 'ldaps') == 'ldaps' else 389),
                    use_ssl=cfg.get('tls', 'ldaps') == 'ldaps',
                    tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg.get('ca_file')),
                    connect_timeout=5, get_info=None)
    bind = AUTO_BIND_NO_TLS if cfg.get('tls', 'ldaps') == 'ldaps' else AUTO_BIND_TLS_BEFORE_BIND
    options = dict(auto_bind=bind, auto_referrals=False, raise_exceptions=True, receive_timeout=5)
    with Connection(server, cfg['bind_dn'], read_secret('CWS_LDAP_BIND_PASSWORD'), **options) as service:
        attribute = cfg.get('username_attribute', 'uid')
        service.search(cfg['base_dn'], f'({attribute}={escape_filter_chars(username)})',
                       search_scope=SUBTREE, attributes=['memberOf'], size_limit=2, time_limit=5)
        if len(service.entries) != 1:
            return None
        entry = service.entries[0]
        groups = entry.entry_attributes_as_dict.get('memberOf', [])
        if cfg['admin_group_dn'].casefold() not in [str(g).casefold() for g in groups]:
            return None
        dn = entry.entry_dn
    # No empty-password/anonymous bind and no reuse of the service identity.
    with Connection(server, dn, password, **options) as user:
        return dn if user.bound else None
