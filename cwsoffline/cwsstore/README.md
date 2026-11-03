# Offline Chrome Web Store

This project is an offline version of the Chrome Web Store, allowing users to browse and download Chrome extensions in a local environment.

## Features

- Browse a list of available Chrome extensions.
- View details of each extension, including descriptions and download links.
- Download CRX files for offline installation.


## Frontends

The store ships two frontends, both served by the same FastAPI app with no
network access needed at runtime:

- `/` - the React single-page storefront with live search and tag/origin
  filtering; the default. Source lives in `frontend/` (Vite + React).
  Also reachable at `/app/`.
- `/classic` - server-rendered pages (Jinja templates). Works with
  JavaScript disabled. Extension detail pages live under
  `/classic/extension/{id}`; legacy `/extension/{id}` links redirect
  there (308). APIs and feeds (`/json`, `/crx`, `/download`, `/assets`,
  `/artifacts`) are unchanged.

The React bundle is prebuilt two ways: the compiled assets are committed
under `app/static/app/` for bare `pip` installs, and the Docker image
rebuilds them from source in a Node build stage (no Node.js in the final
image). After changing `frontend/src`, run `npm run build` in `frontend/`
and commit the result; `npm test` runs the UI test suite.

Classification is assigned where extensions enter the store: entries in
`recommended_extensions.json` or `specified.json` accept optional `tags`
(display taxonomy), `origin` (`webstore` by default; `in-house` for
CRXs placed in the artifacts tree directly, which sync does
not download) and a `description` override. Plain ID strings and
`{id, name}` entries keep working. cwssync resolves this into
`artifacts/extension_metadata.json`, cwsbuild merges it into the index,
and the storefronts read it from `/json`: tag and origin filters in the
React app, badges on the server-rendered pages.

`origin` records where a CRX came from, nothing more: it is not a trust
verdict, and the malicious blocklist applies to in-house entries too. A
declared in-house extension whose CRX is missing from the artifacts tree
is reported as `in_house_missing` and never appears in the store. CRXs
found in the tree with no source entry are labeled `local` (unknown
provenance).

## Source definitions

For a mirrored extension, add its ID to the recommended list or the artifacts
volume's `specified.json`. For an in-house extension, place its CRX at
`artifacts/extensions/<id>/<version>/<id>_<name>_<version>.crx` and add:

```json
[
  {
    "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "name": "Internal tool",
    "origin": "in-house",
    "tags": ["internal", "devtools"],
    "description": "An internal extension."
  }
]
```

Use the extension's real 32-character Chrome ID, not the example ID. Run
`cwssync` to resolve source metadata, then `cwsbuild` to rebuild the catalog.
Do not edit `extensions_info.json`: it is generated. In-house entries are
screened against the local blocklist only; ExtensionTotal scans mirrored Web
Store IDs when configured. Unclassified tree CRXs are labeled `local`.

The browser reads the generated catalog from `/json`. `/artifacts` serves
CRX packages under `extensions/` only, never source definitions or sync reports.
The newest package supplies display metadata and icons; older versions remain
available for download.

## Local development

From the repository root:

```sh
pip install -r requirements.txt
python -m pytest -q
cd cwsoffline/cwsstore/frontend
npm ci
npm test
npm run build
cd ..
CWS_ARTIFACTS_DIR=/absolute/path/to/artifacts \
CWS_ASSETS_DIR=/absolute/path/to/assets \
uvicorn app.main:app --host 127.0.0.1 --port 8005
```

The frontend toolchain requires Node.js 22.12 or newer. Commit the regenerated
`app/static/app` bundle when changing frontend source. Docker builds the
bundle itself and excludes Node from the final runtime. All runtime resources
are local; the GitHub footer link is optional external navigation.

For Docker, Compose, Helm and deployment configuration see the
[repository README](../../README.md). A real Chrome installation/update in the
target air-gapped network, a Helm deployment in the target cluster, and live
ExtensionTotal credentials remain environment-specific acceptance checks.

## License

See [LICENSE](../../LICENSE).
