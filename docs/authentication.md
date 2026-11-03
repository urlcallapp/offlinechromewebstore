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
  By default authorization uses the directory's direct `memberOf` memberships
  (AD or LDAP with that overlay). A regular LDAP user without the admin group is
  denied; regular browsing SSO uses OIDC.

  Nested groups are opt-in via `ldap.nested_groups`:

  - `enabled: true` resolves transitive membership with a portable reverse
    `member` traversal over groupOfNames/groupOfUniqueNames/AD group objects:
    cycle-safe (visited set), bounded by `max_depth` (default 5, maximum 16)
    and `max_groups` (default 128, maximum 4096), over `group_search_base`
    (defaults to `base_dn`). memberUid-only posixGroup schemas are not
    supported. Referrals stay disabled: traversal never leaves the configured
    verified-TLS server. Bounds fail closed.
  - `matching_rule_in_chain: true` instead issues one server-side transitive
    query using the AD/LDS rule OID 1.2.840.113556.1.4.1941. Directories that
    do not implement that rule reject the filter and sign-in fails closed.
    Enable this only for AD/LDS.
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

Sessions follow the usual SSO lifecycle (compare Keycloak's SSO session
idle/max and OAuth2 token refresh), configured with the optional `session`
object:

- `idle_ttl_seconds` (default 900): sliding limit, renewed on authenticated
  activity.
- `max_ttl_seconds` (default 28800): absolute cap from sign-in; activity cannot
  extend a session past it.
- `refresh_interval_seconds` (default 300): authorization re-validation.
  OIDC sessions exchange their refresh token (when the IdP issued one) for
  fresh signed claims, so group changes, user-group removal and IdP-side
  revocation take effect within one interval; `invalid_grant` ends the session.
  Set `oidc.refresh: false` to disable token exchange. LDAP sessions re-check
  directory membership with the read-only service identity; losing the admin
  group ends the session. Transient directory/IdP failures keep the session
  and retry after a minute. Without an IdP refresh token, OIDC group changes
  apply at the next login or session expiry; `max_ttl_seconds` bounds that.
- `max_stale_seconds` (default 3600): authorization freshness cap. A session
  whose group/token re-validation has not succeeded within this window ends
  even while active, so directory/IdP outages fail closed instead of extending
  stale authorization up to the maximum age.

Sessions are bounded, opaque and server-side (`memory` backend only), so one
worker/replica: restart or eviction signs users out. Client-side token sessions
were rejected: with rotating refresh tokens, concurrent requests holding
per-request copies can exchange the same rotated token twice, which IdPs with
reuse detection treat as token-family theft and revoke the whole family during
normal traffic. Multi-replica deployments need a shared session and refresh
coordination store (for example Redis/Valkey with atomic locking); that is a
deliberate deployment decision, not bundled here. Refresh is serialized per
session with an in-process lock, so concurrent requests trigger exactly one
directory lookup or token exchange.

Revocation timing: group removal, user-group loss and IdP-side token revocation
take effect at the next refresh interval, not instantly. Logout invalidates the
server-side session; it does not sign out the upstream IdP SSO session.

Cookies are Secure, HttpOnly, host-only and SameSite=Lax. No password or group
list is sent in the cookie. Logout invalidates the local session, not the
upstream IdP SSO session. LDAP has a five-attempt/minute transport-source
limit; behind an ingress this may be shared by users. Apply organization-level
login throttling as well. No query/access logs should record OIDC codes or
LDAP passwords.

Helm chart 0.4 references an existing ConfigMap (`config.json`) and existing
Secret with keys `gateway-secret`, `ldap-bind-password` and/or
`oidc-client-secret`.  The store mounts only `gateway-secret`. Use the auth values
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
SSO state/PKCE/replay, OIDC refresh-token rotation/group downgrade/user-group
loss/invalid_grant revocation, LDAP escaping/TLS/bind handling, nested-group
traversal depth/cycle/bound behavior and the AD matching-rule path, session
idle sliding/absolute cap/stale-authorization cutoff, refresh serialization
under concurrency, streaming
proxy header sanitization, public update/download behavior, and offline
build/store with network calls denied. Helm renders both Kubernetes and
OpenShift profiles.

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
- https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
- https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
- https://www.keycloak.org/docs/latest/server_admin/#_timeouts
