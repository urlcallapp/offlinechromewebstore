"""Read-only service search, verified TLS, user bind, bounded group membership."""
import ssl
from ldap3 import Server, Connection, Tls, SUBTREE, BASE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.utils.conv import escape_filter_chars
from auth_gateway.config import read_secret

# Covers groupOfNames/groupOfUniqueNames (RFC 4519) and AD "group". memberUid-only
# posixGroup schemas are intentionally unsupported: authorization follows DN members.
GROUP_CLASSES = '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group))'
MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'  # AD/LDS server-side transitive member match.


def _server(cfg):
    return Server(cfg['host'], port=cfg.get('port', 636 if cfg.get('tls', 'ldaps') == 'ldaps' else 389),
                  use_ssl=cfg.get('tls', 'ldaps') == 'ldaps',
                  tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg.get('ca_file')),
                  connect_timeout=5, get_info=None)


def _options(cfg):
    bind = AUTO_BIND_NO_TLS if cfg.get('tls', 'ldaps') == 'ldaps' else AUTO_BIND_TLS_BEFORE_BIND
    return dict(auto_bind=bind, auto_referrals=False, raise_exceptions=True, receive_timeout=5)


def _is_member(cfg, service, user_dn, direct_groups):
    """Direct memberOf, then optional bounded transitive expansion. Fail closed at bounds."""
    target = cfg['admin_group_dn'].casefold()
    if target in [str(g).casefold() for g in direct_groups]:
        return True
    nested = cfg.get('nested_groups') or {}
    if not nested.get('enabled'):
        return False
    if nested.get('matching_rule_in_chain'):
        # One server-side transitive query. Directories without the rule reject it: fail closed.
        service.search(user_dn, f'(member:{MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(cfg["admin_group_dn"])})',
                       search_scope=BASE, attributes=['cn'], size_limit=1, time_limit=5)
        return len(service.entries) == 1
    # Portable reverse-member traversal: cycle-safe, bounded depth and total groups.
    depth_max = nested.get('max_depth', 5)
    count_max = nested.get('max_groups', 128)
    base = nested.get('group_search_base') or cfg['base_dn']
    visited = {user_dn.casefold()}
    frontier = [user_dn]
    for _ in range(depth_max):
        following = []
        for dn in frontier:
            service.search(base, f'(&(member={escape_filter_chars(dn)}){GROUP_CLASSES})',
                           search_scope=SUBTREE, attributes=['cn'], size_limit=count_max, time_limit=5)
            for entry in service.entries:
                group_dn = entry.entry_dn
                if group_dn.casefold() == target:
                    return True
                if group_dn.casefold() not in visited:
                    visited.add(group_dn.casefold())
                    if len(visited) > count_max:
                        return False
                    following.append(group_dn)
        if not following:
            return False
        frontier = following
    return False


def authenticate(cfg, username, password):
    if not username or len(username) > 256 or not password or len(password) > 4096 or '\x00' in username or '\x00' in password:
        return None
    server = _server(cfg)
    with Connection(server, cfg['bind_dn'], read_secret('CWS_LDAP_BIND_PASSWORD'), **_options(cfg)) as service:
        attribute = cfg.get('username_attribute', 'uid')
        service.search(cfg['base_dn'], f'({attribute}={escape_filter_chars(username)})',
                       search_scope=SUBTREE, attributes=['memberOf'], size_limit=2, time_limit=5)
        if len(service.entries) != 1:
            return None
        entry = service.entries[0]
        if not _is_member(cfg, service, entry.entry_dn, entry.entry_attributes_as_dict.get('memberOf', [])):
            return None
        dn = entry.entry_dn
    # No empty-password/anonymous bind and no reuse of the service identity.
    with Connection(server, dn, password, **_options(cfg)) as user:
        return dn if user.bound else None


def recheck_admin(cfg, user_dn):
    """Re-verify membership with the read-only service identity; no password required."""
    if not user_dn or len(user_dn) > 1024 or '\x00' in user_dn:
        return False
    server = _server(cfg)
    with Connection(server, cfg['bind_dn'], read_secret('CWS_LDAP_BIND_PASSWORD'), **_options(cfg)) as service:
        service.search(user_dn, '(objectClass=*)', search_scope=BASE,
                       attributes=['memberOf'], size_limit=1, time_limit=5)
        if len(service.entries) != 1:
            return False
        entry = service.entries[0]
        return _is_member(cfg, service, user_dn, entry.entry_attributes_as_dict.get('memberOf', []))
