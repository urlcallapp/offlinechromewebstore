"""CI-only gateway session fixture. Never copied into runtime images.

Uses the real production gateway factory; inserts a test session instead of
contacting an external IdP. CI mounts only this file into its smoke container.
"""
import time
from auth_gateway.main import create_app

app = create_app()
now = time.time()
app.state.sessions['ci-admin-session'] = (now + 900, {
    'subject': 'ci-admin', 'admin': True, 'csrf': 'ci-only',
    'iat': now, 'lr': now, 'verified_at': now, 'method': 'test',
})
