"""Build cwsstore assets and the extensions_info.json index from mirrored CRX files.

Reads CRX packages from the artifacts tree produced by cwssync:

    artifacts/extensions/<extension_id>/<version>/<id>_<name>_<version>.crx

Extracts each package under the assets directory, reads its manifest.json and
writes artifacts/extensions_info.json consumed by cwsstore. Multiple versions
of the same extension are merged into one entry, newest first.
"""
import json
import logging
import os
import re
import zipfile

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")
# Root-relative fallback icon served by cwsstore's static files.
FALLBACK_ICON_URL = "static/images/icon_144px_blank.png"

ARTIFACTS_DIR = os.environ.get("CWS_ARTIFACTS_DIR", "artifacts")
ASSETS_DIR = os.environ.get("CWS_ASSETS_DIR", "assets")

MALICIOUS_LIST_FILE = os.environ.get(
    "CWS_MALICIOUS_LIST_FILE", os.path.join(ARTIFACTS_DIR, "malicious_extensions.json")
)

# Display metadata (tags, origin, description overrides) resolved by cwssync
# from the store source definitions. Storefront taxonomy only; unrelated to
# the malicious blocklist.
EXTENSION_METADATA_FILE = os.environ.get(
    "CWS_EXTENSION_METADATA_FILE",
    os.path.join(ARTIFACTS_DIR, "extension_metadata.json"),
)


def load_malicious_ids(path=None):
    """IDs on the malicious extension list; empty set when no list exists."""
    path = path or MALICIOUS_LIST_FILE
    if not os.path.exists(path):
        return set()
    with open(path, "r") as handle:
        data = json.load(handle)
    return {
        item["id"] if isinstance(item, dict) else item
        for item in data
        if item
    }


def load_extension_metadata(path=None):
    """Display metadata per extension ID written by cwssync; empty when absent."""
    path = path or EXTENSION_METADATA_FILE
    if not os.path.exists(path):
        return {}
    with open(path, "r") as handle:
        data = json.load(handle)
    return {
        ext_id: metadata for ext_id, metadata in data.items() if isinstance(metadata, dict)
    }


def is_valid_extension_id(value):
    return bool(EXTENSION_ID_PATTERN.match(value or ""))


def parse_crx_filename(filename):
    """Best-effort parse of '<id>_<name>_<version>.crx' or '<id>.crx'."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    parts = stem.split("_")
    extension_id = parts[0]
    name = parts[1].replace("-", " ") if len(parts) > 2 else ""
    version = parts[2] if len(parts) > 2 else (parts[1] if len(parts) == 2 else "")
    return extension_id, name, version


def _is_i18n_placeholder(value):
    return not value or (value.startswith("__MSG_") and value.endswith("__"))


def resolve_name(manifest, fallback):
    """Pick a displayable name, skipping __MSG_*__ i18n placeholders."""
    for candidate in (
        manifest.get("name"),
        manifest.get("action", {}).get("default_title"),
        fallback,
    ):
        if candidate and not _is_i18n_placeholder(candidate):
            return candidate
    return fallback


def resolve_description(manifest):
    description = manifest.get("description", "")
    return "" if _is_i18n_placeholder(description) else description


def resolve_icon(manifest, dest_path, extension_id):
    """Return the root-relative URL of the largest icon that exists on disk."""
    icons = manifest.get("icons", {})
    try:
        sizes = sorted(icons.keys(), key=int, reverse=True)
    except ValueError:
        sizes = []
    for size in sizes:
        relative = icons[size].lstrip("/")
        if os.path.exists(os.path.join(dest_path, relative)):
            return f"assets/{extension_id}/{relative}"
    return FALLBACK_ICON_URL


def _version_sort_key(version_string):
    try:
        return Version(version_string)
    except InvalidVersion:
        return Version("0")


def extract_crx(crx_path, dest_path):
    """Extract a CRX (which is a ZIP with a header) and return its manifest."""
    with zipfile.ZipFile(crx_path, "r") as archive:
        archive.extractall(dest_path)
    manifest_path = os.path.join(dest_path, "manifest.json")
    if not os.path.exists(manifest_path):
        raise ValueError(f"manifest.json missing in {crx_path}")
    with open(manifest_path, "r") as handle:
        return json.load(handle)


def _artifacts_url(crx_path, artifacts_dir):
    """Root-relative URL under the store's /artifacts mount, forward slashes."""
    relative = os.path.relpath(crx_path, artifacts_dir)
    return "artifacts/" + relative.replace(os.sep, "/")


def build_index(src_folder=None, dest_folder=None, artifacts_dir=None):
    """Walk the artifacts tree and return the extensions_info index list."""
    src_folder = src_folder or os.path.join(artifacts_dir or ARTIFACTS_DIR, "extensions")
    dest_folder = dest_folder or ASSETS_DIR
    artifacts_dir = artifacts_dir or ARTIFACTS_DIR

    extensions = {}
    extension_metadata = load_extension_metadata(
        os.environ.get(
            "CWS_EXTENSION_METADATA_FILE",
            os.path.join(artifacts_dir or ARTIFACTS_DIR, "extension_metadata.json"),
        )
    )
    malicious_path = os.environ.get(
        "CWS_MALICIOUS_LIST_FILE", os.path.join(artifacts_dir, "malicious_extensions.json")
    )
    malicious_ids = load_malicious_ids(malicious_path)
    if malicious_ids:
        logger.info("Excluding %d malicious extensions", len(malicious_ids))

    for root, _, files in os.walk(src_folder):
        for file in sorted(files):
            if not file.endswith(".crx"):
                continue
            crx_path = os.path.join(root, file)
            file_id, file_name, file_version = parse_crx_filename(file)
            if not is_valid_extension_id(file_id):
                logger.warning("Skipping file with unexpected name: %s", crx_path)
                continue
            if file_id in malicious_ids:
                logger.info("Skipping malicious extension: %s", file_id)
                continue

            dest_path = os.path.join(dest_folder, file_id)
            os.makedirs(dest_path, exist_ok=True)
            try:
                manifest = extract_crx(crx_path, dest_path)
            except (zipfile.BadZipFile, ValueError, KeyError) as exc:
                logger.error("Skipping unreadable CRX %s: %s", crx_path, exc)
                continue

            version = manifest.get("version") or file_version
            metadata = extension_metadata.get(file_id, {})
            # A source-entry description wins over the manifest one; tags and
            # origin classify the extension for filtering. CRXs dropped into
            # the tree without any source entry are "local".
            entry = extensions.setdefault(
                file_id,
                {
                    "name": resolve_name(manifest, file_name or file_id),
                    "extension_id": file_id,
                    "description": metadata.get("description")
                    or resolve_description(manifest),
                    "image_path_url": resolve_icon(manifest, dest_path, file_id),
                    "tags": [str(tag) for tag in metadata.get("tags", [])],
                    "origin": metadata.get("origin") or "local",
                    "versions": [],
                },
            )
            entry["versions"].append(
                {"version": version, "path_url": _artifacts_url(crx_path, artifacts_dir)}
            )
            logger.info("Indexed %s %s", file_id, version)

    for entry in extensions.values():
        entry["versions"].sort(
            key=lambda item: _version_sort_key(item["version"]), reverse=True
        )
    return sorted(extensions.values(), key=lambda item: item["name"].lower())


def save_extensions_info(extensions_info, output_file):
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as json_file:
        json.dump(extensions_info, json_file, indent=4)
    logger.info("Wrote %s (%d extensions)", output_file, len(extensions_info))


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    extensions_info = build_index()
    save_extensions_info(
        extensions_info, os.path.join(ARTIFACTS_DIR, "extensions_info.json")
    )


if __name__ == "__main__":
    main()
