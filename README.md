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
    docker compose up cwsbuild
    ```

2. Run the cwsstore service, ensuring the artifacts are accessible to the service.

    ``` bash
    docker compose up cwsstore -d
    ```
3. Configure chrome policy to add **_http://cws_intranet_domain/*_** as **ExtensionInstallSources**, see [Configure GPO](#configure-gpo) section
4. Open Chrome, hopefully you can magically install extensions.

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
- *See [ExtensionInstallAllowlist](https://chromeenterprise.google/policies/?policy=ExtensionInstallAllowlist) chrome policy to configure allowlist for enhanced security*
- *See [ExtensionInstallSources](https://chromeenterprise.google/policies/#ExtensionInstallSources) chrome policy to configure source for custom offline store url*
- *See [ExtensionInstallForcelist](https://chromeenterprise.google/policies/#ExtensionInstallForcelist) to force install extenions from `https://cws_domain/crx`*

---

Possible Implements TODO List:
* - [X] Add test cases.
* - [X] ExtensionTotal get malicious extensions
* - [X] crx expand and create json job for cwsstore
* - [X] add helm (kubernetes) support
* - [X] fix extension container properties alignments
* - [X] list of manually specified extensions (artifacts/specified.json)
* - [X] implements malicious extension list
* - [X] check possibility to implement configure DNS in a air gapped env to https://clients2.google.com/service/update2/crx and https://chromewebstore.google.com when chrome uses HSTS - see [docs/airgapped-dns.md](docs/airgapped-dns.md) (research; live verification in a real air-gapped network still open)

## Configuration

All components are configured with environment variables:

| Variable | Default | Used by | Purpose |
| --- | --- | --- | --- |
| `CWS_ARTIFACTS_DIR` | `artifacts` | all | Mirrored CRX tree and generated indexes |
| `CWS_ASSETS_DIR` | `assets` | cwsbuild, cwsstore | Extracted store assets (icons) |
| `CWS_RECOMMENDED_EXTENSIONS_FILE` | `recommended_extensions.json` | cwssync | Recommended extensions to mirror |
| `CWS_SPECIFIED_EXTENSIONS_FILE` | `<artifacts>/specified.json` | cwssync | Manually specified extensions (same format) |
| `CWS_MALICIOUS_LIST_FILE` | `<artifacts>/malicious_extensions.json` | cwssync, cwsbuild | Malicious extension blocklist |
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
(objects with `id` and `name`, or plain ID strings). Manual entries override
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
`cwsoffline/cwsstore/app/static/extensions/` serve as fixtures.

## Kubernetes (Helm)

``` bash
helm install cws helm/offlinechromewebstore
```

Deploys shared artifacts/assets PVCs, the cwssync Deployment, a cwsbuild hook
Job and the cwsstore Deployment + Service. For an air-gapped cluster, set
`cwssync.enabled=false` and populate the artifacts PVC externally. See
`helm/offlinechromewebstore/values.yaml` for all options.