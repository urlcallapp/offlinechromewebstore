"""Resolve the latest stable Chrome version from Google's version history API."""
import logging

import requests
from packaging import version as pkg_version

logger = logging.getLogger(__name__)

VERSION_HISTORY_URL = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/"
    "{platform}/channels/stable/versions"
)


def get_latest_chrome_version(platform="linux", timeout=30):
    """Return the latest stable Chrome version for *platform*, or None on failure."""
    url = VERSION_HISTORY_URL.format(platform=platform)
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        # Includes requests' JSONDecodeError, a RequestException subclass.
        logger.warning("Error fetching Chrome version: %s", exc)
        return None
    except ValueError as exc:
        logger.warning("Error parsing Chrome version response: %s", exc)
        return None

    if not isinstance(data, dict):
        logger.warning("Unexpected Chrome version response payload: %r", type(data).__name__)
        return None

    candidates = []
    entries = data.get("versions", [])
    if not isinstance(entries, list):
        logger.warning("Chrome version response 'versions' is not a list")
        return None
    for entry in entries:
        raw = entry.get("version") if isinstance(entry, dict) else None
        if not raw:
            continue
        try:
            candidates.append((pkg_version.parse(raw), raw))
        except pkg_version.InvalidVersion:
            logger.warning("Ignoring unparsable Chrome version %r", raw)

    if not candidates:
        logger.warning("No Chrome versions found in the API response")
        return None
    return sorted(candidates, reverse=True)[0][1]
