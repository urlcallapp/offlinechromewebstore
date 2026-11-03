"""Offline, short-lived gateway assertions. No outbound auth or trusted user headers."""
import os
from pathlib import Path

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def secret():
    path = os.environ.get('CWS_ADMIN_GATEWAY_SECRET_FILE')
    if not path:
        return None
    value = Path(path).read_text().strip()
    if len(value) < 32:
        raise RuntimeError('Admin gateway secret must have at least 32 characters')
    return value


def assertion(key, method, path):
    return URLSafeTimedSerializer(key, salt='cws-admin-v1').dumps({'method': method, 'path': path})


async def require_admin(request: Request):
    key = secret()
    if not key:
        raise HTTPException(503, 'Admin login is not configured')
    try:
        data = URLSafeTimedSerializer(key, salt='cws-admin-v1').loads(
            request.headers.get('X-CWS-Admin-Assertion', ''), max_age=30)
        if data != {'method': request.method, 'path': request.url.path}:
            raise BadSignature('Wrong operation')
    except (BadSignature, SignatureExpired):
        raise HTTPException(403, 'Use the authenticated admin gateway') from None
