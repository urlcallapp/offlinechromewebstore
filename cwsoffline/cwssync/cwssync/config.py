"""Runtime configuration for cwssync, loaded from environment variables."""
import os

# Base update URL used both to resolve versions and to download CRX files.
CHROME_STORE_URL = os.environ.get(
    "CWS_CHROME_STORE_URL", "https://clients2.google.com/service/update2/crx"
)

# Public web store detail page, used as a best-effort name lookup fallback.
WEBSTORE_DETAIL_URL = os.environ.get(
    "CWS_WEBSTORE_DETAIL_URL", "https://chromewebstore.google.com/detail"
)

# Directory where mirrored CRX artifacts are written.
ARTIFACTS_DIR = os.environ.get("CWS_ARTIFACTS_DIR", "artifacts")

# JSON file with the recommended extensions to mirror.
RECOMMENDED_EXTENSIONS_FILE = os.environ.get(
    "CWS_RECOMMENDED_EXTENSIONS_FILE", "recommended_extensions.json"
)

# Optional JSON file with manually specified extensions to mirror on top of
# the recommended list. Defaults to specified.json inside the artifacts dir,
# so it can be dropped in next to the mirrored content.
SPECIFIED_EXTENSIONS_FILE = os.environ.get(
    "CWS_SPECIFIED_EXTENSIONS_FILE", os.path.join(ARTIFACTS_DIR, "specified.json")
)

# Chrome version sent as prodversion to the update service. When unset, the
# latest stable version is resolved via chrome_version.get_latest_chrome_version.
CHROME_PROD_VERSION = os.environ.get("CWS_CHROME_PROD_VERSION")

# Fallback Chrome version when auto-detection fails.
FALLBACK_CHROME_PROD_VERSION = "131.0.0.0"


def _get_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(
            f"Environment variable {name} must be an integer, got {raw!r}"
        )


# HTTP timeout in seconds for all outbound requests.
REQUEST_TIMEOUT = _get_int("CWS_REQUEST_TIMEOUT", 30)

# Hours between scheduled sync runs.
SYNC_INTERVAL_HOURS = _get_int("CWS_SYNC_INTERVAL_HOURS", 24)

USER_AGENT = os.environ.get(
    "CWS_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)

# Sync output: display metadata (tags and origin) for the extensions in the
# store, consumed by cwsbuild when it writes extensions_info.json. This is
# storefront taxonomy, not a security verdict: the malicious blocklist lives
# in malicious_extensions.json and is enforced separately.
EXTENSION_METADATA_FILE = os.environ.get(
    "CWS_EXTENSION_METADATA_FILE", os.path.join(ARTIFACTS_DIR, "extension_metadata.json")
)
