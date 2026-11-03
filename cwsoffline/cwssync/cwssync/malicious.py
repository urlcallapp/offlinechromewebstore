"""Malicious extension detection and exclusion.

Two sources are combined:

1. A local blocklist JSON file (default artifacts/malicious_extensions.json)
   that can be maintained by hand and is also written back with API findings.
2. The ExtensionTotal risk API, when EXTENSIONTOTAL_API_KEY is configured.

An extension is excluded when it is on the local list or its API risk score
reaches CWS_RISK_THRESHOLD (default 70).
"""
import json
import logging
import os

from . import config
from .extensiontotal import ExtensionTotalClient

logger = logging.getLogger(__name__)


def _get_threshold():
    raw = os.environ.get("CWS_RISK_THRESHOLD", "70")
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"CWS_RISK_THRESHOLD must be an integer, got {raw!r}")


RISK_THRESHOLD = _get_threshold()

MALICIOUS_LIST_FILE = os.environ.get(
    "CWS_MALICIOUS_LIST_FILE",
    os.path.join(config.ARTIFACTS_DIR, "malicious_extensions.json"),
)


class MaliciousList:
    """Persistent list of extensions that must not be mirrored."""

    def __init__(self, path=None):
        self.path = path or MALICIOUS_LIST_FILE
        self.entries = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r") as handle:
            data = json.load(handle)
        # accept both [{id, ...}] and ["id", ...] shapes
        result = {}
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                result[item["id"]] = item
            elif isinstance(item, str):
                result[item] = {"id": item, "reason": "manual"}
        return result

    def __contains__(self, extension_id):
        return extension_id in self.entries

    def add(self, extension_id, reason, risk=None):
        entry = {"id": extension_id, "reason": reason}
        if risk is not None:
            entry["risk"] = risk
        self.entries[extension_id] = entry

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as handle:
            json.dump(list(self.entries.values()), handle, indent=4)


class MaliciousChecker:
    """Combines the local list with optional ExtensionTotal risk lookups."""

    def __init__(self, malicious_list=None, client=None, threshold=None):
        self.malicious_list = malicious_list or MaliciousList()
        self.client = client if client is not None else ExtensionTotalClient()
        self.threshold = threshold if threshold is not None else RISK_THRESHOLD

    def is_malicious(self, extension_id):
        """True when the extension must be excluded from mirroring."""
        if extension_id in self.malicious_list:
            logger.info("Skipping %s: on the malicious extension list", extension_id)
            return True
        if not self.client.available:
            return False
        try:
            report = self.client.get_extension_risk(extension_id)
        except Exception as exc:
            # Fail open on API errors: a broken risk service must not stop
            # the sync, and the local list still applies.
            logger.warning("Risk lookup failed for %s: %s", extension_id, exc)
            return False
        risk = report.get("risk")
        if isinstance(risk, (int, float)) and risk >= self.threshold:
            logger.warning(
                "Skipping %s: ExtensionTotal risk %s >= threshold %s",
                extension_id,
                risk,
                self.threshold,
            )
            self.malicious_list.add(extension_id, reason="extensiontotal", risk=risk)
            return True
        return False
