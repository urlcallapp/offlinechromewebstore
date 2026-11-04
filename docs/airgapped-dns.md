# Air-gapped DNS redirection of the Chrome Web Store endpoints - feasibility

Research for the README TODO: "check possibility to implement configure DNS in
an air gapped env to https://clients2.google.com/service/update2/crx and
https://chromewebstore.google.com when chrome uses HSTS."

Status: research findings with sources, not yet verified against a live Chrome
in a real air-gapped network.

## Short answer

You do not need DNS redirection. Chrome's extension policies accept an
arbitrary internal update URL, including plain HTTP, which is the supported
way to point managed browsers at cwsstore. DNS redirection of the Google
endpoints is possible on fully managed devices, but it is the fragile and
unnecessary route.

## The supported route (no DNS tricks)

- `ExtensionInstallForcelist` entries are `<extension-id>;<update-url>`, and
  per the policy definition in the Chromium source "The update URL should use
  one of the following schemes: http, https or file." An internal
  `http://cws.intra/crx` is therefore a valid forcelist update URL.
  Source: components/policy/.../ExtensionInstallForcelist.yaml in
  chromium/src (chromium.googlesource.com).
- The forcelist update URL is only used for the initial install. Ongoing
  updates follow the update URL inside the extension's manifest, which can be
  overridden per extension with the `ExtensionSettings` policy's `update_url`
  field. Source: support.google.com/chrome/a/answer/9867568.
- `ExtensionInstallSources` allowlists the internal store origin so the store
  UI can trigger installs. See examples/policy/ in this repository.

This covers both functions the TODO wants from DNS redirection: initial
installs and ongoing updates from an internal server.

## If DNS redirection is attempted anyway

Two conditions decide whether `clients2.google.com` (update service) and
`chromewebstore.google.com` (store UI) can be pointed at a private server:

### 1. HSTS

- Checked against `net/http/transport_security_state_static.json` in
  chromium/src @ main (2026-11-03): neither `google.com`,
  `clients2.google.com` nor `chromewebstore.google.com` has a static
  (preloaded) HSTS entry.
- HSTS for these names is only learned dynamically from a response header, so
  a Chrome profile that has never reached the real google.com - the normal
  situation in an air-gapped network - carries no HSTS state for them.
- Machines that did visit the real google.com may hold dynamic HSTS with
  `includeSubDomains`; dynamic entries can be cleared per machine or avoided
  with fresh managed profiles.

### 2. Certificates

- If HTTPS is enforced anyway (dynamic HSTS, or simply browsing to https://),
  a private server cannot present a publicly trusted certificate for a Google
  name.
- On managed devices an enterprise root CA can be installed locally and issue
  the certificate; Certificate Transparency only applies to publicly trusted
  CAs, and locally installed roots are exempt
  (googlechrome.github.io/CertificateTransparency/enterprises.html).
- Chrome removed its static Google key pins years ago, so locally rooted
  interception is no longer blocked by pinning.

### What this does NOT establish

That interception actually works. Absence of a static HSTS entry is only one
precondition. Dynamic HSTS state carried from previous real-Google visits,
per-browser handling of locally installed roots, certificate name/policy
checks and Chrome version behavior can each still block the connection, and
none of that was verified against a live browser. Treat "enterprise CA + DNS
override" as an unproven hypothesis, not a guaranteed route. Even if it works,
it reimplements what the extension policies already give you, and spoofing
`chromewebstore.google.com` additionally means mirroring a complex dynamic web
app, not just the update protocol.

## Recommendation

- Point Chrome at cwsstore with `ExtensionInstallForcelist` /
  `ExtensionSettings.update_url` / `ExtensionInstallSources` (see
  examples/policy/). No DNS changes required.
- DNS redirection stays an unverified hypothesis for environments where
  policies cannot be pushed but DNS can; it would need a live managed-device
  experiment before anyone relies on it.

## Sources

- ExtensionInstallForcelist policy definition, chromium/src:
  https://chromium.googlesource.com/chromium/src/+/HEAD/components/policy/resources/templates/policy_definitions/Extensions/ExtensionInstallForcelist.yaml
- Configure ExtensionSettings policy:
  https://support.google.com/chrome/a/answer/9867568
- Certificate Transparency for Enterprises:
  https://googlechrome.github.io/CertificateTransparency/enterprises.html
- Chromium static HSTS list (checked 2026-11-03):
  https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json
- HSTS preload semantics:
  https://developer.chrome.com/docs/lighthouse/best-practices/has-hsts
