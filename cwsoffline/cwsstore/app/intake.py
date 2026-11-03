"""First-party CRX upload intake: validate, bound, stage for the offline build.

The store writes ONLY to the intake directory, never to artifacts/assets.
A cwsbuild run consumes intake files into the artifacts tree (CWS_INTAKE_DIR).
Header/identity checks mirror cwsbuild's: they establish format consistency,
NOT package authenticity - Chrome verifies signatures at install/update time.
"""
import hashlib
import io
import json
import logging
import os
import re
import struct
import tempfile
import zipfile

logger = logging.getLogger(__name__)

INTAKE_DIR = os.environ.get("CWS_INTAKE_DIR", "")
MAX_UPLOAD = min(int(os.environ.get("CWS_INTAKE_MAX_BYTES", str(200 * 1024 * 1024))), 512 * 1024 * 1024)
if MAX_UPLOAD <= 0:
    raise ValueError("CWS_INTAKE_MAX_BYTES must be positive")
MAX_CRX_HEADER_SIZE = 1024 * 1024
MAX_MANIFEST_SIZE = 1024 * 1024
ID = re.compile(r"[a-p]{32}\Z")
# Chrome extension versions: 1-4 dot-separated integers, each 0-65535.
VERSION = re.compile(r"(0|[1-9]\d{0,4})(\.(0|[1-9]\d{0,4})){0,3}\Z")
SAFE_NAME = re.compile(r"[^A-Za-z0-9.]+")


class InvalidPackage(Exception):
    """Package failed structural validation; refuse with a 4xx, never a 500."""


def _id_from_bytes(raw):
    return "".join(chr(ord("a") + int(nibble, 16)) for nibble in raw.hex())


def _protobuf_fields(data):
    offset = 0

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise InvalidPackage("truncated protobuf varint")
            byte = data[offset]
            offset += 1
            if shift == 63 and byte > 1:
                raise InvalidPackage("protobuf varint overflow")
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise InvalidPackage("protobuf varint overflow")

    fields = {}
    while offset < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not 0 < number < (1 << 29):
            raise InvalidPackage("invalid protobuf field number")
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else (8 if wire == 1 else 4)
            if length > len(data) - offset:
                raise InvalidPackage("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        else:
            raise InvalidPackage("unsupported protobuf wire type")
        fields.setdefault(number, []).append((wire, value))
    return fields


def _single_bytes(fields, number, label):
    values = fields.get(number, [])
    if len(values) != 1 or values[0][0] != 2 or not values[0][1]:
        raise InvalidPackage(f"missing, duplicate or invalid {label}")
    return values[0][1]


def crx_identity(payload):
    """Return the extension ID from CRX2/3 header bytes. Structural checks only."""
    if len(payload) < 16 or payload[:4] != b"Cr24":
        raise InvalidPackage("missing CRX header (unsigned ZIPs are not supported)")
    version, size = struct.unpack("<II", payload[4:12])
    offset = 12
    if version == 3:
        if not 0 < size <= MAX_CRX_HEADER_SIZE or len(payload) < offset + size + 4:
            raise InvalidPackage("invalid or oversized CRX3 header")
        fields = _protobuf_fields(payload[offset:offset + size])
        offset += size
        signed = _protobuf_fields(_single_bytes(fields, 10000, "signed_header_data"))
        raw_id = _single_bytes(signed, 1, "crx_id")
        if len(raw_id) != 16:
            raise InvalidPackage("CRX3 crx_id must be 16 bytes")
        extension_id = _id_from_bytes(raw_id)
        matches_key = False
        # At least one developer proof must match crx_id; store proofs may differ.
        for wire, proof in fields.get(2, []) + fields.get(3, []):
            if wire != 2:
                raise InvalidPackage("invalid CRX3 proof wire type")
            proof_fields = _protobuf_fields(proof)
            key = _single_bytes(proof_fields, 1, "public_key")
            _single_bytes(proof_fields, 2, "signature")
            matches_key |= _id_from_bytes(hashlib.sha256(key).digest()[:16]) == extension_id
        if not matches_key:
            raise InvalidPackage("CRX3 crx_id has no matching developer public key")
    elif version == 2:
        if len(payload) < offset + 4:
            raise InvalidPackage("truncated CRX2 header")
        signature_size = struct.unpack("<I", payload[offset:offset + 4])[0]
        offset += 4
        if not size or not signature_size or size + signature_size > MAX_CRX_HEADER_SIZE:
            raise InvalidPackage("invalid or oversized CRX2 header")
        if len(payload) < offset + size + signature_size + 4:
            raise InvalidPackage("truncated CRX2 key or signature")
        key = payload[offset:offset + size]
        offset += size + signature_size
        extension_id = _id_from_bytes(hashlib.sha256(key).digest()[:16])
    else:
        raise InvalidPackage(f"unsupported CRX version {version}")
    if payload[offset:offset + 4] != b"PK\x03\x04":
        raise InvalidPackage("CRX header is not followed by a ZIP archive")
    return extension_id, payload[offset:]


def read_manifest(zip_bytes):
    """Read only manifest.json from the package payload, strictly bounded."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            info = next((entry for entry in archive.infolist() if entry.filename == "manifest.json"), None)
            if info is None:
                raise InvalidPackage("manifest.json missing in package")
            if info.file_size > MAX_MANIFEST_SIZE:
                raise InvalidPackage("oversized manifest.json")
            with archive.open(info) as handle:
                manifest = json.loads(handle.read(MAX_MANIFEST_SIZE + 1))
    except zipfile.BadZipFile as exc:
        raise InvalidPackage("package payload is not a readable ZIP") from exc
    except json.JSONDecodeError as exc:
        raise InvalidPackage("manifest.json is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise InvalidPackage("manifest.json must be an object")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version) or any(int(n) > 65535 for n in version.split(".")):
        raise InvalidPackage("manifest version must be 1-4 dot-separated integers (0-65535)")
    name = manifest.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 256 or "\x00" in name:
        raise InvalidPackage("manifest needs a bounded name")
    return version, name.strip()


def sanitize_name(name):
    cleaned = SAFE_NAME.sub("-", name).strip("-.")[:64]
    return cleaned or "extension"


def stage_upload(payload, blocked_ids):
    """Validate and atomically stage an uploaded CRX into the intake tree."""
    if not INTAKE_DIR:
        raise RuntimeError("Upload intake is not configured on this store")
    if not payload or len(payload) > MAX_UPLOAD:
        raise InvalidPackage(f"package must be 1 byte to {MAX_UPLOAD} bytes")
    extension_id, zip_bytes = crx_identity(payload)
    if extension_id in blocked_ids:
        raise InvalidPackage("this extension is on the malicious blocklist")
    version, name = read_manifest(zip_bytes)
    target_dir = os.path.join(INTAKE_DIR, extension_id, version)
    filename = f"{extension_id}_{sanitize_name(name)}_{version}.crx"
    os.makedirs(target_dir, exist_ok=True)
    handle, temp_path = tempfile.mkstemp(dir=target_dir, prefix=".upload-")
    try:
        with os.fdopen(handle, "wb") as staging:
            staging.write(payload)
        os.replace(temp_path, os.path.join(target_dir, filename))
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
    logger.info("Staged uploaded extension %s version %s (%d bytes)", extension_id, version, len(payload))
    return {"extension_id": extension_id, "version": version, "name": name,
            "filename": filename, "size": len(payload)}


def list_uploads():
    """Currently staged uploads, newest paths first."""
    if not INTAKE_DIR or not os.path.isdir(INTAKE_DIR):
        return []
    staged = []
    for extension_id in sorted(os.listdir(INTAKE_DIR)):
        if not ID.fullmatch(extension_id):
            continue
        for version in sorted(os.listdir(os.path.join(INTAKE_DIR, extension_id)), reverse=True):
            folder = os.path.join(INTAKE_DIR, extension_id, version)
            if not os.path.isdir(folder):
                continue
            for filename in sorted(os.listdir(folder)):
                path = os.path.join(folder, filename)
                if filename.endswith(".crx") and os.path.isfile(path):
                    staged.append({"extension_id": extension_id, "version": version,
                                   "filename": filename, "size": os.path.getsize(path)})
    return staged


def delete_upload(extension_id, version):
    """Remove one staged upload; strict identifiers, intake-contained only."""
    if not INTAKE_DIR:
        raise RuntimeError("Upload intake is not configured on this store")
    if not ID.fullmatch(extension_id or "") or not VERSION.fullmatch(version or ""):
        raise InvalidPackage("invalid extension ID or version")
    root = os.path.realpath(INTAKE_DIR)
    folder = os.path.realpath(os.path.join(root, extension_id, version))
    if not folder.startswith(root + os.sep) or not os.path.isdir(folder):
        raise InvalidPackage("no such staged upload")
    removed = 0
    for filename in os.listdir(folder):
        if filename.endswith(".crx"):
            os.unlink(os.path.join(folder, filename))
            removed += 1
    for path in (folder, os.path.join(root, extension_id)):
        try:
            os.rmdir(path)
        except OSError:
            pass
    logger.info("Removed staged upload %s version %s (%d files)", extension_id, version, removed)
    return removed
