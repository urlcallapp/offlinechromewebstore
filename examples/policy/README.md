# Offline Chrome policy exports

Open `/admin` on your local store for a read-only policy builder. Select a store
origin reachable by managed clients, choose the default explicitly, and select
extensions/modes. Preview before downloading:

- GPO JSON: compact **ExtensionSettings value only**, one line, no wrapper.
- Linux JSON: `{"ExtensionSettings": {...}}` (plus a `3rdparty` block when
  extension managed policy is selected) for managed-policy deployment.
- Windows .reg: machine-registry import for direct testing. It is NOT a
  GPMC/GPO import format.
- GPO PowerShell: merges the same values into YOUR existing named GPO with
  `Set-GPRegistryValue`. The store never runs it; running it modifies the named
  GPO. It refuses to run until you set the GPO name, and never creates, deletes
  or links GPOs.
- Forcelist/install-sources references: legacy formats ExtensionSettings
  overrides; never deploy both strategies together.
- Allowlist reference: selected non-blocked IDs, not a standalone policy file.
- Review bundle: all formats, warnings, source links and the selected origin.

## Uploading your own extensions

`/admin` also stages first-party CRX uploads (your own or vetted packages) when
the store runs with `CWS_INTAKE_DIR` set (the Docker images and Helm chart set
it to a dedicated intake volume). Uploads are checked for CRX structure,
manifest version shape and the malicious blocklist, then land in the intake
directory only. Structure is not authenticity: upload only packages you trust.
The next `cwsbuild` run revalidates and moves staged files into
`artifacts/extensions/<id>/<version>/`, so they index, serve and update like
synced packages. The store never writes to the artifacts or assets trees.

## Extension managed policy

The spec's optional `extension_policies` object (`{"<id>": {...values...}}`)
sets an extension's own managed configuration, validated against the
`storage.managed_schema` declared in that extension's built manifest. Types,
enums, required keys and closed objects are enforced; values for extensions
without a declared schema are refused. Values land under
`HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<id>\policy`
in the .reg/PowerShell exports and under `3rdparty.extensions` in the Linux
JSON. Chrome performs the final validation at runtime; complex constraint
keywords (patterns, ranges, lengths) are reported as not enforced here.

This is a policy generator, not an authenticated device-management service. It
has no saved policies, device inventory, device changes, remote fetches, or
secret storage. Put the whole store behind your normal intranet access controls.
Generated policy includes only available local CRXs; newly blocked IDs are
refused and blocklist entries override a permissive default. Malformed blocklist
input refuses export rather than silently generating a permissive policy.

## Offline CLI

Run from the repository root, with a complete current local catalog and the
matching blocklist. Make `empty-blocklist.json` contain `[]` only if your snapshot
has no blocklist. Do not omit a real blocklist.

```sh
python cwsoffline/cwsstore/app/policy.py \
  --spec examples/policy/selection.json \
  --catalog artifacts/extensions_info.json \
  --blocklist artifacts/malicious_extensions.json --format bundle > review.json
```

Add `--assets-dir assets` when the spec uses `extension_policies`.

Use `--format gpo`, `--format linux`, or `--format allowlist` for the individual
outputs. CLI generation is standard-library-only and does not import sync code.
The CLI trusts the supplied catalog snapshot; the HTTP generator additionally
checks the CRX still exists. Neither verifies an actual device installation.
`selection.json` and `extension_policy.json` are **examples**, not production
approvals: replace the origin, IDs, and modes for your organization.

## Deployment and safety

For Windows Group Policy, install the current Chrome ADMX templates. Under
Administrative Templates > Google > Google Chrome > Extensions, enable
**Extension management settings** and paste the single-line GPO value. Do not
paste the Linux wrapper or review bundle. Follow your organization's normal GPO
review, scoping, backup and rollback process.

For Linux Chrome, install the Linux JSON in
`/etc/opt/chrome/policies/managed/`; Chromium uses its distribution-specific
managed policy directory, commonly `/etc/chromium/policies/managed/`. These
changes need administrator access. Review `chrome://policy` after policy reload.

- `allowed` permits installation; it does not install or redirect updates and
  does not bypass Chrome's off-store installation restrictions. Use an explicit
  `normal_installed` or `force_installed` selection for managed automatic
  installation from this store. Both set `/crx` and `override_update_url:true`
  so subsequent updates do not revert to a manifest's public Web Store URL.
- `normal_installed` permits disabling; `force_installed` prevents user removal
  or disabling. The generator never chooses either for you.
- `blocked` can disable an already-installed extension. `removed` and automatic
  uninstall are intentionally not offered. Changing an existing force-install
  policy can still change device behavior: test rollback on a pilot group.
- Default `blocked` is allowlist-only behavior via ExtensionSettings. That policy
  overrides legacy ExtensionInstallAllowlist, Blocklist, Forcelist and Sources.
  Merge with existing policy deliberately; do not stack conflicting strategies.
- Google support documents AD-domain membership for automatic off-store Windows
  installs. Current Chromium policy sources also list Azure AD joining or Chrome
  Enterprise Core enrollment for force installation. Confirm your actual Chrome
  version, management status and OS eligibility rather than assuming any Windows
  machine can install a self-hosted CRX. macOS has management restrictions too.
- Prefer HTTPS with a certificate trusted by clients. Do not use `0.0.0.0`,
  localhost, browser-supplied Host headers or public Google URLs as the origin.
  Origin must have no path, credentials, query or fragment. Path-prefix hosting
  is not supported by these exports or the root-relative storefront.
- Test initial installation **and a later update** on managed Chrome. These
  generated files do not constitute live Chrome/GPO acceptance.

## Sources

- https://support.google.com/chrome/a/answer/9867568?hl=en
- https://support.google.com/chrome/a/answer/7532015
- https://support.google.com/chrome/a/answer/7517525
- https://www.chromium.org/administrators/policy-list-3/extension-settings-full/
- https://chromium.googlesource.com/chromium/src/+/HEAD/components/policy/resources/templates/policy_definitions/Extensions/ExtensionInstallForcelist.yaml
