"""Build cwsstore assets and the extensions_info.json index from mirrored CRX files.

Reads CRX packages recursively, deriving identity from their CRX2/3 headers.
First-party packages may have any filename. cwssync convention:

    artifacts/extensions/<extension_id>/<version>/<id>_<name>_<version>.crx

Extracts each package under the assets directory, reads its manifest.json and
writes artifacts/extensions_info.json consumed by cwsstore. Multiple versions
of the same extension are merged into one entry, newest first.
"""
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import tempfile
import zipfile

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

EXTENSION_ID_PATTERN = re.compile(r"[a-p]{32}")
# Bound all untrusted header allocations; no network or protobuf dependency.
MAX_CRX_HEADER_SIZE = 1024 * 1024
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
    return bool(EXTENSION_ID_PATTERN.fullmatch(value or ""))


def parse_crx_filename(filename):
    """Best-effort parse of '<id>_<name>_<version>.crx' or '<id>.crx'."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    parts = stem.split("_")
    extension_id = parts[0]
    name = parts[1].replace("-", " ") if len(parts) > 2 else ""
    version = parts[2] if len(parts) > 2 else (parts[1] if len(parts) == 2 else "")
    return extension_id, name, version


def _id_from_bytes(raw):
    return "".join(chr(ord("a") + int(nibble, 16)) for nibble in raw.hex())


def _key_id(key):
    return _id_from_bytes(hashlib.sha256(key).digest()[:16])


def _protobuf_fields(data):
    """Read bounded protobuf wire fields, rejecting truncation and groups."""
    offset = 0

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[offset]
            offset += 1
            if shift == 63 and byte > 1:
                raise ValueError("protobuf varint overflow")
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("protobuf varint overflow")

    fields = {}
    while offset < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not 0 < number < (1 << 29):
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else (8 if wire == 1 else 4)
            if length > len(data) - offset:
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError("unsupported protobuf wire type")
        fields.setdefault(number, []).append((wire, value))
    return fields


def _single_bytes(fields, number, label):
    values = fields.get(number, [])
    if len(values) != 1 or values[0][0] != 2 or not values[0][1]:
        raise ValueError(f"missing, duplicate or invalid {label}")
    return values[0][1]


def read_crx_id(crx_path):
    """Extract CRX2/3 identity and check key/header consistency, NOT signatures.

    Header bytes, public keys and signature bytes remain untrusted. Chrome
    must still verify signatures at install/update; this is not an audit of
    package authenticity, safety, or publisher ownership.
    """
    with open(crx_path, "rb") as handle:
        prefix = handle.read(12)
        if len(prefix) != 12 or prefix[:4] != b"Cr24":
            raise ValueError("missing CRX header (unsigned ZIPs are not supported)")
        version, size = struct.unpack("<II", prefix[4:])
        if version == 3:
            if not 0 < size <= MAX_CRX_HEADER_SIZE:
                raise ValueError("invalid or oversized CRX3 header")
            header = handle.read(size)
            if len(header) != size:
                raise ValueError("truncated CRX3 header")
            fields = _protobuf_fields(header)
            signed = _protobuf_fields(_single_bytes(fields, 10000, "signed_header_data"))
            raw_id = _single_bytes(signed, 1, "crx_id")
            if len(raw_id) != 16:
                raise ValueError("CRX3 crx_id must be 16 bytes")
            extension_id = _id_from_bytes(raw_id)
            matches_key = False
            # Store packages may contain additional publisher proofs whose
            # hashes differ. At least one developer proof must match crx_id.
            for wire, proof in fields.get(2, []) + fields.get(3, []):
                if wire != 2:
                    raise ValueError("invalid CRX3 proof wire type")
                proof_fields = _protobuf_fields(proof)
                key = _single_bytes(proof_fields, 1, "public_key")
                _single_bytes(proof_fields, 2, "signature")
                matches_key |= _key_id(key) == extension_id
            if not matches_key:
                raise ValueError("CRX3 crx_id has no matching developer public key")
        elif version == 2:
            signature_size_raw = handle.read(4)
            if len(signature_size_raw) != 4:
                raise ValueError("truncated CRX2 header")
            signature_size = struct.unpack("<I", signature_size_raw)[0]
            if not size or not signature_size or size + signature_size > MAX_CRX_HEADER_SIZE:
                raise ValueError("invalid or oversized CRX2 header")
            key = handle.read(size)
            signature = handle.read(signature_size)
            if len(key) != size or len(signature) != signature_size:
                raise ValueError("truncated CRX2 key or signature")
            extension_id = _key_id(key)
        else:
            raise ValueError(f"unsupported CRX version {version}")
        if handle.read(4) != b"PK\x03\x04":
            raise ValueError("CRX header is not followed by a ZIP archive")
    return extension_id


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
        root = os.path.realpath(dest_path)
        candidate = os.path.realpath(os.path.join(root, relative))
        if candidate.startswith(root + os.sep) and os.path.isfile(candidate):
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
            try:
                extension_id = read_crx_id(crx_path)
                if is_valid_extension_id(file_id) and file_id != extension_id:
                    raise ValueError(
                        f"filename ID {file_id} does not match CRX ID {extension_id}"
                    )
            except (ValueError, OSError) as exc:
                logger.error("Skipping CRX with invalid identity %s: %s", crx_path, exc)
                continue
            if extension_id in malicious_ids:
                logger.info("Skipping malicious extension: %s", extension_id)
                continue
            # Filename display hints only apply to the historical ID naming
            # convention. Arbitrary first-party filenames need no ID or layout.
            if not is_valid_extension_id(file_id):
                file_name, file_version = "", ""
            file_id = extension_id

            # Inspect each version in isolation. Only the newest valid package
            # supplies display metadata and assets; old files cannot overwrite
            # its icons or leave stale extracted files behind.
            os.makedirs(dest_folder, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=dest_folder) as staging:
                try:
                    manifest = extract_crx(crx_path, staging)
                    version = manifest.get("version") or file_version
                    if not version:
                        raise ValueError("missing version")
                except (zipfile.BadZipFile, ValueError, KeyError, OSError) as exc:
                    logger.error("Skipping unreadable CRX %s: %s", crx_path, exc)
                    continue
                metadata = extension_metadata.get(file_id, {})
                entry = extensions.get(file_id)
                newest = not entry or _version_sort_key(version) > _version_sort_key(entry["versions"][0]["version"])
                if newest:
                    dest_path = os.path.join(dest_folder, file_id)
                    if os.path.exists(dest_path):
                        shutil.rmtree(dest_path)
                    shutil.copytree(staging, dest_path)
                    versions = entry["versions"] if entry else []
                    entry = extensions[file_id] = {
                        "name": resolve_name(manifest, file_name or file_id),
                        "extension_id": file_id,
                        "description": metadata.get("description") or resolve_description(manifest),
                        "image_path_url": resolve_icon(manifest, dest_path, file_id),
                        "tags": [str(tag) for tag in metadata.get("tags", [])],
                        "origin": metadata.get("origin") or "local",
                        "versions": versions,
                    }
                entry["versions"].append(
                    {"version": version, "path_url": _artifacts_url(crx_path, artifacts_dir)}
                )
                entry["versions"].sort(key=lambda item: _version_sort_key(item["version"]), reverse=True)
            logger.info("Indexed %s %s", file_id, version)

    for entry in extensions.values():
        entry["versions"].sort(
            key=lambda item: _version_sort_key(item["version"]), reverse=True
        )
    return sorted(extensions.values(), key=lambda item: item["name"].lower())


# Strict Chrome version shape for staged uploads; intake rejects anything else.
UPLOAD_VERSION = re.compile(r"(0|[1-9]\d{0,4})(\.(0|[1-9]\d{0,4})){0,3}\Z")
UPLOAD_FILENAME = re.compile(r"[A-Za-z0-9._-]+\Z")
INTAKE_DIR = os.environ.get("CWS_INTAKE_DIR", "")


def consume_intake(intake_dir=None, artifacts_dir=None):
    """Move validated staged uploads from the intake tree into artifacts.

    The store's upload endpoint stages first-party CRXs in CWS_INTAKE_DIR.
    Each build revalidates identity and version, then moves them under
    artifacts/extensions/<id>/<version>/ so they index and serve like synced
    packages. Invalid files stay in intake for an admin to review or delete.
    """
    intake_dir = intake_dir if intake_dir is not None else INTAKE_DIR
    artifacts_dir = artifacts_dir or ARTIFACTS_DIR
    if not intake_dir or not os.path.isdir(intake_dir):
        return 0
    consumed = 0
    for root, _, files in os.walk(intake_dir):
        for filename in sorted(files):
            if not filename.endswith(".crx"):
                continue
            source = os.path.join(root, filename)
            try:
                if not UPLOAD_FILENAME.fullmatch(filename):
                    raise ValueError("unsafe filename")
                extension_id = read_crx_id(source)
                with tempfile.TemporaryDirectory() as staging:
                    manifest = extract_crx(source, staging)
                version = manifest.get("version")
                if not isinstance(version, str) or not UPLOAD_VERSION.fullmatch(version):
                    raise ValueError(f"invalid manifest version {version!r}")
                target_dir = os.path.join(artifacts_dir, "extensions", extension_id, version)
                os.makedirs(target_dir, exist_ok=True)
                shutil.move(source, os.path.join(target_dir, filename))
                consumed += 1
                logger.info("Consumed uploaded extension %s %s", extension_id, version)
            except (ValueError, OSError, zipfile.BadZipFile, KeyError) as exc:
                logger.error("Refusing staged upload %s: %s (left in intake)", source, exc)
    return consumed


def save_extensions_info(extensions_info, output_file):
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as json_file:
        json.dump(extensions_info, json_file, indent=4)
    logger.info("Wrote %s (%d extensions)", output_file, len(extensions_info))


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    consume_intake()
    extensions_info = build_index()
    save_extensions_info(
        extensions_info, os.path.join(ARTIFACTS_DIR, "extensions_info.json")
    )


if __name__ == "__main__":
    main()
