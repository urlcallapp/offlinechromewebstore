"""Resolve the latest stable Chrome version from Google's version history API."""
import json
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
        logger.warning("Error fetching Chrome version: %s", exc)
        return None
    except json.JSONDecodeError as exc:
        logger.warning("Error parsing Chrome version response: %s", exc)
        return None

    versions = [
        entry["version"]
        for entry in data.get("versions", [])
        if entry.get("version")
    ]
    if not versions:
        logger.warning("No Chrome versions found in the API response")
        return None
    return sorted(versions, key=pkg_version.parse, reverse=True)[0]
