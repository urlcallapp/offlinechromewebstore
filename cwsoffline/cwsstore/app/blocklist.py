"""Malicious extension blocklist enforcement for cwsstore.

cwsbuild already excludes blocked IDs from the index it writes. This module
is the second line of defense: it filters them out of any (possibly stale)
index being served and refuses direct CRX downloads of blocked IDs.
"""
import json
import os

from app import config

MALICIOUS_LIST_FILE = os.environ.get(
    "CWS_MALICIOUS_LIST_FILE",
    os.path.join(config.ARTIFACTS_DIR, "malicious_extensions.json"),
)


def load_blocked_ids():
    """IDs on the blocklist; empty set when no list exists."""
    if not os.path.exists(MALICIOUS_LIST_FILE):
        return set()
    try:
        with open(MALICIOUS_LIST_FILE, "r") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return set()
    return {
        item["id"] if isinstance(item, dict) else item
        for item in data
        if item
    }


def filter_extensions(extensions):
    """Drop blocklisted entries from an index list."""
    blocked = load_blocked_ids()
    if not blocked:
        return extensions
    return [
        ext for ext in extensions if ext.get("extension_id") not in blocked
    ]
