<img src="cwsoffline/cwsstore/app/static/images/favicon.png" alt="cws icon" width="200" height="200"/>

# Offline Chrome Web Store


# Chrome Web Store - Offline Store, Builder and Updater 


This enables Chrome Web Store's web presence to be mirrored for seamless use in an offline environment (e.g. air-gapped), or to run a private web store.

## Features

On the Internet connected system , **cwssync** will:
* Mirror the Chrome Extensions across platforms (Windows|Linux|Darwin);
* Mirror recommended/typical extensions from the Chrome Web Store;
* Mirror the malicious extension list.
* Optionally, mirror all extensions (--syncall, rather than the default of --sync).

On the non-Internet connected system, **cwsbuild**:
* Implements UI store assets (images and metadata) from CRX files;
* Implements the updater interface to enable use of first party extensions.

On the non-Internet connected system, **cwsstore**:
* Implements the updater interface to enable offline updating.
* Implements the extension API to enable offline extension use.
* Implements initial support for multiple versions.
* Supports custom/private extensions (follow the structure of a mirrored extension).
* Impliments `/crx` like https://clients2.google.com/service/update2/crx
* Impliments `/json` route for view raw properties of extenions and api scripting capabilities.



## Online/offline boundary

Only **cwssync** runs in the Internet-connected environment. It downloads CRXs,
resolves source metadata, and optionally checks Web Store IDs with ExtensionTotal.
The ExtensionTotal API key belongs only on that online sync host. Do not transfer
the key or configure it on cwsbuild/cwsstore.

Transfer the **artifacts directory**, not just individual CRXs, across the
boundary. Preserve the `extensions/<id>/<version>/*.crx` paths and include
`extension_metadata.json` (origin, tags and description) and
`malicious_extensions.json` (the local blocklist), when present. Without these
sidecars CRXs can still be built, but source labels fall back to `local` and
there are no transferred blocklist decisions. Copy a completed sync snapshot,
not files still being written by a running sync.

Inside the air-gapped/offline environment, **cwsbuild** reads those local CRXs
and sidecars, extracts icons/metadata and writes `extensions_info.json` plus
`assets/`. It never calls ExtensionTotal or the Web Store. **cwsstore** serves
those local files, update feeds and the bundled UI without outbound Internet
access. The local blocklist remains enforced by both build and store. Remote
risk lookups are not part of offline-store acceptance.

Build the images online (or in a separate build environment); image builds
install dependencies and are not an offline runtime step. On the
offline host, preload the cwsbuild/cwsstore images, then use the air-gapped
Compose file explicitly so cwssync is not started:

```bash
docker compose -f docker-compose-ag.yaml run --rm --no-deps --pull never cwsbuild
docker compose -f docker-compose-ag.yaml up --no-deps --pull never -d cwsstore
```

The builder has networking disabled in this Compose file. The store needs only
inbound access from local clients; restrict its outbound traffic using your
network/cluster policy. For Helm, set `cwssync.enabled=false`, preload the images
and populate the artifacts PVC before the build Job runs. No live ExtensionTotal
key or service is required in that cluster.

## Requirements
* Docker (ideally with docker-compose for simplicity)

## Getting Started - Full Offline Use - Using Docker Containers

There are three components, **cwssync** which mirrors the content on an Internet connected system, **cwsbuild** which build assets for UI store from crx files (1st and 3rd party) and **cwsstore** which provides the necessary APIs and endpoints necessary to support Chrome Extensions use. While it is designed for offline environments, it is possible, with some DNS trickery, that this could be operated as a "corporate" Chrome Web Store.

On the Internet connected system:

1. Acquire/mirror the Docker containers (cwssync / cwsbuild / cwsstore). 

    `docker-compose pull`
    
2. Setup and run the cwssync service on the Internet connected system.
    * Ensuring the artifact directory is accessible to whatever transfer mechanism you will use and cwssync.
    * Run cwssync service and ensure the artifacts are generated.
    * Wait for the sync to complete. You should see 'Sync completed' and that it is sleeping when the artifacts have finished downloading.

    ``` bash
    docker compose up cwssync
    ```

3. Copy the artifacts to the non-Internet connected system.

On the non-Internet connected system:
1. Run the **cwsbuild** service to build assets

    ``` bash
    docker compose -f docker-compose-ag.yaml run --rm --no-deps --pull never cwsbuild
    ```

2. Run the cwsstore service, ensuring the artifacts are accessible to the service.

    ``` bash
    docker compose -f docker-compose-ag.yaml up --no-deps --pull never -d cwsstore
    ```
3. Open `/admin` and generate a reviewed policy for your managed clients. See [policy exports](examples/policy/README.md).
4. Deploy the policy through your approved management process and test installation and a subsequent update on managed Chrome. Allowlisting alone does not bypass platform restrictions.

#### Run with docker compose
``` bash
docker compose build
docker compose run cwssync
docker compose up -d cwsbuild cwsstore
```

#### How to build
```bash
# build cwssync
docker build -t cwssync -f cwsoffline/cwssync/Dockerfile .
# build cwsbuild
docker build -t cwsbuild -f cwsoffline/cwsbuild/Dockerfile .
# build cwsstore
docker build -t cwsstore -f cwsoffline/cwsstore/Dockerfile ./cwsoffline/cwsstore/
```

#### How to run with docker
``` bash
# Run the container
docker run -it -v $(pwd)/artifacts:/app/artifacts cwssync

# Run cwsbuild
docker run -it -v $(pwd)/artifacts:/app/artifacts -v $(pwd)/assets:/app/assets cwsbuild

# Run cwsstore
docker run -it -v $(pwd)/artifacts:/store/artifacts -v $(pwd)/assets:/store/assets -p 8005:8005 cwsstore
```

#### Cleanup
``` bash
# Remove cwssync exited and running images
docker ps -a | grep -E ^cws | awk '{print $1}' | xargs docker rm -f

# Remove artifacts folder after using docker
sudo rm -rf artifacts
```

#### Configure GPO

Use the offline [policy export builder](examples/policy/README.md) at `/admin`,
or the standard-library CLI, to generate compact ExtensionSettings for Windows
GPO, Linux managed-policy JSON and an allowlist reference. All install modes
and default behavior require an explicit admin choice. Nothing is applied or
saved by the generator. Review existing policies and platform restrictions
before distribution.

Helm is already supported. See the [chart deployment guide](helm/offlinechromewebstore/README.md)
for air-gapped values, optional enforced runtime egress denial, TLS and scheduling.

---

Possible Implements TODO List (status: implemented / verified):
* - [X] Add test cases - implemented and verified by the offline regression suite.
* - [X] ExtensionTotal get malicious extensions - implemented; verified against the client contract in tests, NOT yet against the live ExtensionTotal API (needs an API key).
* - [X] crx expand and create json job for cwsstore - pre-existing; re-verified by the cwsbuild tests.
* - [X] add helm (kubernetes) support - implemented; validated with helm lint/template only, NOT yet deployed to a live cluster.
* - [X] fix extension container properties alignments - implemented; verified with rendered desktop and mobile screenshots.
* - [X] list of manually specified extensions (artifacts/specified.json) - implemented and verified by tests.
* - [X] implements malicious extension list - implemented and verified by tests (sync skip, index exclusion, store-side serving refusal).
* - [X] check possibility to implement configure DNS in a air gapped env to https://clients2.google.com/service/update2/crx and https://chromewebstore.google.com when chrome uses HSTS - research documented in [docs/airgapped-dns.md](docs/airgapped-dns.md); NOT yet verified against a live Chrome in an air-gapped network.

Verification: actual Docker image builds and a containerized fixture
build/download smoke test passed on main in
[Verify run 41639043329](https://github.com/urlcallapp/offlinechromewebstore/actions/runs/41639043329).
The offline regression suite also builds and serves real CRX fixtures in a fresh
process with outbound connections/DNS blocked, without importing cwssync, both
with and without transferred metadata/blocklist sidecars.

Remaining target-environment checks: an end-to-end Chrome install/update cycle
against the deployed cwsstore (see [docs/update-protocol.md](docs/update-protocol.md))
and a live Helm deployment. Separately, the optional online cwssync
ExtensionTotal integration still needs a live API key for acceptance testing;
that does not block offline cwsbuild/cwsstore operation.

## Configuration

All components are configured with environment variables:

| Variable | Default | Used by | Purpose |
| --- | --- | --- | --- |
| `CWS_ARTIFACTS_DIR` | `artifacts` | all | Mirrored CRX tree and generated indexes |
| `CWS_ASSETS_DIR` | `assets` | cwsbuild, cwsstore | Extracted store assets (icons) |
| `CWS_RECOMMENDED_EXTENSIONS_FILE` | `recommended_extensions.json` | cwssync | Recommended extensions to mirror |
| `CWS_SPECIFIED_EXTENSIONS_FILE` | `<artifacts>/specified.json` | cwssync | Manually specified extensions (same format) |
| `CWS_MALICIOUS_LIST_FILE` | `<artifacts>/malicious_extensions.json` | cwssync, cwsbuild, cwsstore | Local malicious extension blocklist |
| `CWS_CHROME_PROD_VERSION` | auto-detected | cwssync | Chrome `prodversion` sent to the update service |
| `CWS_SYNC_INTERVAL_HOURS` | `24` | cwssync | Hours between scheduled sync runs |
| `CWS_REQUEST_TIMEOUT` | `30` | cwssync | HTTP timeout in seconds |
| `EXTENSIONTOTAL_API_KEY` | unset | cwssync | ExtensionTotal risk API key (optional) |
| `CWS_RISK_THRESHOLD` | `70` | cwssync | Risk score at which an extension is blocked |

cwssync CLI: `--once` (single sync, no scheduler), `--sync` (incremental,
default), `--syncall` (force re-download of everything).

### Manually specified extensions

Drop a `specified.json` into the artifacts directory to mirror extensions
beyond the recommended list. Same format as `recommended_extensions.json`
(objects with `id` and `name`, or plain ID strings). Optional `tags`,
`origin` and `description` fields are documented in the
[store guide](cwsoffline/cwsstore/README.md). Manual entries override
recommended ones with the same ID.

### Malicious extensions

Extensions on the malicious list are skipped by cwssync and excluded from the
store index by cwsbuild. The list is a JSON file (objects with `id`, plus
`reason` / `risk`) that can be maintained by hand at
`artifacts/malicious_extensions.json`. When `EXTENSIONTOTAL_API_KEY` is set,
cwssync also queries the ExtensionTotal risk API and adds extensions at or
above `CWS_RISK_THRESHOLD` to the list automatically. Without a key, or when
the API errors, syncing continues with the local list only.

## Testing

``` bash
pip install -r requirements.txt   # dev/test environment
python -m pytest tests/ -v
```

The suite is fully offline: HTTP calls are mocked and the two CRX files under
`tests/fixtures/` serve as fixtures.

## Kubernetes (Helm)

``` bash
helm install cws helm/offlinechromewebstore
```

Deploys shared artifacts/assets PVCs, the cwssync Deployment, a cwsbuild hook
Job and the cwsstore Deployment + Service. For an air-gapped cluster, set
`cwssync.enabled=false` and populate the artifacts PVC externally. See
`helm/offlinechromewebstore/values.yaml` for all options.

Pull requests and main pushes run `.github/workflows/verify.yaml`: Python and
frontend tests, dependency audit, reproducible frontend build, and actual Docker
image builds plus a containerized fixture build/download smoke test. This
workflow never publishes images or calls a live extension risk service. Passing
local unit tests is not evidence that the Docker job has passed.


### First-party CRX identity (offline)

Drop a **packed CRX3** under `artifacts/extensions/` (subdirectories are
optional), for example `artifacts/extensions/internal/MyTool.crx`, then run
`cwsbuild` as usual. No extension ID is required in the filename or directory.
The name and version come from `manifest.json`. The original CRX bytes and path
are preserved for download and updates; packages are never re-signed or renamed.

`cwsbuild` derives the ID from the CRX3 header's 16-byte `crx_id` and checks
that at least one developer public-key hash matches it. Additional publisher
proofs are allowed. Legacy CRX2 identity is derived from its public key; this
is parsing compatibility, not a promise that current Chrome accepts CRX2.
Keep the same private signing key for future versions to retain the same ID.
Do not copy the private key into the artifacts directory.

Existing `<id>.crx` and `<id>_<name>_<version>.crx` filenames continue to work.
When the first underscore-delimited segment is a valid 32-character `a`-`p` ID,
it **must match** the header-derived ID. A mismatch is logged and the package
is excluded before assets, metadata, blocklist checks or update entries can be
assigned to a wrong ID. The blocklist and optional `extension_metadata.json`
classification use the derived ID, including for arbitrarily named packages.
Directory names and a manifest `key` are never used as an identity fallback.
For local in-house metadata, key the sidecar by this derived ID. If you also
use cwssync's in-house inventory declarations, its existing
`extensions/<id>/<version>/*.crx` inventory convention still applies; sync does
not discover arbitrary first-party paths or upload them to the Web Store.

Malformed/truncated/oversized headers, unsupported CRX versions, missing proof
fields, key/ID conflicts, and plain unsigned ZIPs renamed `.crx` are explicitly
logged and skipped. Pack unsigned source with a signing key first. There is no
fallback to a trusted-looking filename. Rebuild the index after changing files;
builds can contain valid entries even if other packages were skipped, so inspect
the logs for exclusions.

**Security limit:** this is identity extraction and structural consistency
checking, **not cryptographic signature verification**. Header, key and signature
bytes remain untrusted; an attacker can forge internally consistent fields.
A parsed ID does not prove publisher ownership, package integrity, safety, or
installability. Chrome still performs its own install/update validation. Only
import CRXs through your approved review process. No online service is contacted
by cwsbuild or cwsstore for identity checks.

Format references: [Chromium CRX3 schema](https://chromium.googlesource.com/chromium/src/+/HEAD/components/crx_file/crx3.proto)
and [Chromium ID algorithm](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/crx_file/id_util.cc).

### OpenShift Helm profile

Chart 0.3 adds an opt-in restricted-security pod profile and edge-TLS OpenShift
Route. Compose `values-openshift.yaml` with `values-airgapped.yaml` when offline;
OpenShift by itself does not disable sync. No SCC/anyuid grants or fixed
namespace UID/fsGroup are created. See [Helm OpenShift setup and acceptance
checks](helm/offlinechromewebstore/README.md#openshift-profile-chart-03).
Route rendering and security tests are not live OpenShift admission, PVC,
router/certificate, or Chrome-install verification.
