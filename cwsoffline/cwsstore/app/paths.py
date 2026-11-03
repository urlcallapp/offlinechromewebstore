"""Constrain extension file access to its canonical, unblocked ID tree."""
import os
import re
from pathlib import Path

from app.blocklist import load_blocked_ids

ID = re.compile(r"[a-p]{32}\Z")


def guarded_path(root_dir, file_path, id_position):
    # Reject normalization aliases before checking IDs; resolve symlinks before
    # containment checks. Artifacts exposes CRX packages only, not sync reports,
    # source definitions or other operational files in the same volume.
    parts = file_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) <= id_position + 1 or not ID.fullmatch(parts[id_position]):
        return None
    if parts[id_position] in load_blocked_ids():
        return None
    if id_position == 1 and (parts[0] != "extensions" or not file_path.endswith(".crx")):
        return None
    root = Path(root_dir).resolve()
    candidate = root.joinpath(*parts)
    # Do not serve through symlinks, even aliases inside the same root: they
    # could cross from an allowed extension into a blocked extension's files.
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        candidate.resolve().relative_to(root)
    except (ValueError, OSError, RuntimeError):
        return None
    return os.fspath(candidate) if candidate.is_file() else None
