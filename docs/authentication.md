# Central login and public Chrome endpoints

The store has no local admin password or first-login account. Admin routes now
fail closed when no auth gateway signing key is configured. This is a deliberate
change from the earlier open policy-export tool. Admin still only generates
reviewable policy exports; it does not save selections or apply device policy.

## Two login methods, separate authorization

Run `auth_gateway.main:create_app --factory` in a separate process/container:

- Direct LDAP admin login: a read-only service identity searches for exactly one
  user, checks direct `memberOf` membership in `admin_group_dn`, then binds as
  that user to verify their password. Verified LDAPS or StartTLS is mandatory.
  Referrals, anonymous/empty-password binds and plaintext fallback are disabled.
  Filters escape user input. Connections/searches have timeouts and size bounds.
  This first implementation requires a directory exposing direct `memberOf`
  memberships (AD or LDAP with that overlay). Nested groups and groupOfNames-only
  schemas are not implemented. A regular LDAP user without the admin group is
  denied; regular browsing SSO uses OIDC.
- Generic OIDC SSO: authorization-code flow with PKCE S256, state and nonce;
  Authlib validates signed ID tokens, issuer, audience, expiry and nonce. The
  configured issuer must use HTTPS. `admin_groups` is a mandatory explicit
  allowlist. Other authenticated users can browse but cannot export policy.
  `user_groups`, if present, restricts all SSO access to those groups. Include
  the admin group in that list if admins should also sign in. Group claim must
  be a list of strings. No email-domain inference or automatic admin promotion.

Enable either method or both by including their objects in the config. Remove
the unused object. No external vendor is required. SAML is supported **through
an external SAML-to-OIDC broker**, not as a native SAML SP in this repository.
For example an organization's existing broker can accept SAML upstream and
expose OIDC here. Configure trust, metadata, signatures and group mapping at the
broker. Do not label this native SAML or point the OIDC issuer at a SAML URL.

## UI policy versus machine policy

`access: anonymous` keeps browsing public; `access: users-only` requires SSO for
UI, JSON catalog, API detail, static UI and image routes. Admin is always gated
by authentication **and admin membership** in either mode. A signed method/path
bound assertion (30-second maximum age) lets the gateway call the offline store.
Client identity/authorization headers are stripped, not trusted. A direct store
call cannot bypass the protected backend when `CWS_STORE_ACCESS=users-only`.

As requested, automatic Chrome update/install requests do not require a browser
SSO session. The exact public machine set is:

- `GET`, `HEAD`, `POST` `/crx` (and its canonical trailing-slash redirect).
- `GET`, `HEAD` `/download/<32-character Chrome ID>`.
- `GET`, `HEAD` `/artifacts/extensions/<ID>/<version>/<filename>.crx`, the package
  URLs emitted by the update feed, still subject to existing filesystem and
  malicious-extension blocklist checks.

This is **not private extension distribution**. Anyone with network access can
request the feed and CRX bytes in either mode, including first-party packages.
The public feed exposes extension IDs/versions/package URLs. No arbitrary
artifact files, catalog JSON, risk reports or admin paths get that exemption.
Use network segmentation/firewalls to restrict machine access if needed. There
is no machine-token, mTLS-device or per-device authorization feature here.

Set `CWS_PUBLIC_ORIGIN` on the store to the exact trusted client-facing HTTPS
origin when using the gateway. It keeps update codebase URLs on the correct
HTTPS origin; don't derive that origin from untrusted forwarded headers.

## Deployment

`examples/auth/config.json` is a nonsecret schema example, not ready-to-use IdP
configuration. Use your real issuer, client ID, exact redirect URI
`https://<store-origin>/auth/callback`, group claims and directory settings.
Register a confidential authorization-code client with PKCE support. Grant only
the scopes/claims needed. No discovery, signing-key, issuer or TLS verification
bypass is provided. For an internal CA use the system trust store for OIDC and
`ldap.ca_file` for LDAP; mount public CA certificates into the config directory.

Secrets are files, never committed config or Helm values:

- `CWS_ADMIN_GATEWAY_SECRET_FILE`: strong random shared signing secret of at
  least 32 characters, available only to gateway/store. Rotate it on both.
- `CWS_LDAP_BIND_PASSWORD_FILE`: only when LDAP enabled.
- `CWS_OIDC_CLIENT_SECRET_FILE`: only when OIDC enabled.

The gateway's sessions are bounded, opaque, server-side and expire after 15
minutes. Cookies are Secure, HttpOnly, host-only and SameSite=Lax. No password,
OIDC token or group list is sent in the cookie. Logout invalidates the local
session, not the upstream IdP SSO session. Directory/IdP group removal takes
effect at the next login or session expiry; there is no instant revocation feed.
Only one gateway worker/replica is supported; restart or eviction signs users
out. Do not scale it without adding a shared server-side session/rate-limit
store. LDAP has a five-attempt/minute transport-source limit; behind an ingress
this may be shared by users. Apply organization-level login throttling as well.
No query/access logs should record OIDC codes or LDAP passwords.

Helm chart 0.4 references an existing ConfigMap (`config.json`) and existing
Secret with keys `gateway-secret`, `ldap-bind-password` and/or
`oidc-client-secret`. The store mounts only `gateway-secret`. Use the auth values
example and a tested source-built store image, not an assumed updated `latest`.
Ingress/Route target the gateway Service when enabled; backend Service remains
ClusterIP. The gateway uses the same built image with a different command.
OpenShift restricted settings also apply to the gateway. No SCC grant is added.

The airgap deny-egress policy still selects only build/store. Authentication
needs separate gateway access to the **internal** directory/IdP and store. It
must not gain internet access merely to make SSO work. Configure CNI/firewall
rules for only those destinations, account for DNS and additive policies, and
verify them in your target cluster. Gateway must reach a trusted backend over
isolated pod/service networking (or HTTPS with trusted certificates). Signed
assertions do not encrypt proxy traffic or prevent replay within 30 seconds;
protect that network and secret. Backend assertions are never logged.

For Compose use `docker-compose-auth.yaml` with the normal/airgap compose file,
set nonsecret origin/access/config/secret-directory environment variables and
terminate HTTPS at a trusted reverse proxy targeting loopback port 8006. The
base Compose file still publishes port 8005; firewall/remove that publication
in production. Backend checks protect admin/SSO UI, but public machine bytes
remain reachable by design. Do not accidentally expose HTTP login port 8006.

Admin POSTs require the exact configured Origin; LDAP login also requires a
session CSRF token. Local logout: obtain CSRF via `/auth/session`, then POST
`/auth/logout` with `X-CSRF-Token` and the exact Origin. SSO callbacks are state,
nonce and PKCE protected, with a fixed callback origin, not a user redirect URL.

## Validation and limits

Tests cover anonymous/admin/non-admin boundaries, direct-backend and forged
header denial, signed-token issuer/audience/expiry/nonce/signature validation,
SSO state/PKCE/replay, LDAP escaping/TLS/bind handling, streaming proxy header
sanitization, public update/download behavior, and offline build/store with
network calls denied. Helm renders both Kubernetes and OpenShift profiles.

This is not a live organization integration result. Before rollout test real
LDAP schema/certificates/groups, real IdP login/logout/claim mapping/key rotation,
TLS and reverse proxy, SCC/storage/router/CNI, gateway restart, session expiry,
and a managed Chrome install and subsequent update. No live provider, directory,
cluster, image release or deployment is performed by this change.

References:
- https://docs.authlib.org/en/stable/oauth2/client/web/starlette.html
- https://ldap3.readthedocs.io/en/latest/ssltls.html
- https://ldap3.readthedocs.io/en/latest/searches.html
- https://openid.net/specs/openid-connect-core-1_0.html
- https://www.keycloak.org/docs/latest/server_admin/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
