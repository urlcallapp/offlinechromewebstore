"""Runtime configuration for cwsstore, loaded from environment variables."""
import os

# Directory containing extensions_info.json and the mirrored CRX tree.
ARTIFACTS_DIR = os.environ.get("CWS_ARTIFACTS_DIR", "artifacts")

# Directory containing extracted extension assets (icons) built by cwsbuild.
ASSETS_DIR = os.environ.get("CWS_ASSETS_DIR", "assets")

EXTENSIONS_FILE = os.path.join(ARTIFACTS_DIR, "extensions_info.json")

# URL prefix under which artifacts are served; path_url values in
# extensions_info.json are relative to this prefix.
ARTIFACTS_URL_PREFIX = "artifacts/"
