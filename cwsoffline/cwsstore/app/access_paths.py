"""Exact public machine endpoints, shared by the offline store and auth edge."""
import re

ID = r'[a-p]{32}'
DOWNLOAD = re.compile(r'/download/' + ID + r'\Z')
CRX = re.compile(r'/artifacts/extensions/' + ID + r'/[^/]+/[^/]+\.crx\Z')


def machine_request(method, path):
    if path in {'/crx', '/crx/'}:
        return method in {'GET', 'POST', 'HEAD'}
    if method not in {'GET', 'HEAD'} or any(part in {'.', '..'} for part in path.split('/')) or '\\' in path or '%' in path:
        return False
    return bool(DOWNLOAD.fullmatch(path) or CRX.fullmatch(path))
