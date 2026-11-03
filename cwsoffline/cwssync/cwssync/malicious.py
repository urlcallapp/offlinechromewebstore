"""Malicious extension detection and exclusion.

Sources combined:

1. A local blocklist JSON file (default artifacts/malicious_extensions.json)
   maintained by hand and written back with API findings.
2. The ExtensionTotal risk API, only when EXTENSIONTOTAL_API_KEY is set.

Exclusion semantics:

- An ID on the local list is always blocked. Nothing downloads it, cwsbuild
  never indexes it and cwsstore never serves it, no matter how it was
  requested (recommended, manually specified, or already mirrored earlier).
- With no API key configured the scanner is simply absent: extensions sync
  normally and the state is logged once as scanning disabled.
- With an API key configured, a lookup that fails is an outage, not a clean
  verdict: the extension is skipped for this run, counted separately as a
  scan error, recorded in the sync report as scan_error and never written to
  the blocklist. --once exits nonzero so the failure is visible.
"""
import enum
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


class ScanStatus(enum.Enum):
    BLOCKED_LISTED = "blocked_listed"      # on the local blocklist
    BLOCKED_RISK = "blocked_risk"          # API risk at/above threshold
    CLEAN = "clean"                        # API risk below threshold
    SCAN_UNAVAILABLE = "scan_unavailable"  # no API key configured, scanner absent
    SCAN_ERROR = "scan_error"              # scanner configured but lookup failed


# Statuses under which an extension may be downloaded.
DOWNLOADABLE = {ScanStatus.CLEAN, ScanStatus.SCAN_UNAVAILABLE}


class MaliciousList:
    """Persistent list of extensions that must not be mirrored or served."""

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
        self._announced_absent = False

    def check(self, extension_id):
        """Return the ScanStatus for *extension_id*."""
        if extension_id in self.malicious_list:
            logger.info("Skipping %s: on the malicious extension list", extension_id)
            return ScanStatus.BLOCKED_LISTED
        if not self.client.available:
            if not self._announced_absent:
                logger.info(
                    "EXTENSIONTOTAL_API_KEY not set: risk scanning disabled, "
                    "only the local blocklist applies"
                )
                self._announced_absent = True
            return ScanStatus.SCAN_UNAVAILABLE
        try:
            report = self.client.get_extension_risk(extension_id)
        except Exception as exc:
            # A configured scanner that fails is an outage, not a clean
            # verdict. The extension is skipped this run and reported as
            # scan_error; it is never written to the blocklist.
            logger.error(
                "Risk scan failed for %s (scanner configured): %s", extension_id, exc
            )
            return ScanStatus.SCAN_ERROR
        risk = report.get("risk")
        if isinstance(risk, (int, float)) and risk >= self.threshold:
            logger.warning(
                "Blocking %s: ExtensionTotal risk %s >= threshold %s",
                extension_id,
                risk,
                self.threshold,
            )
            self.malicious_list.add(extension_id, reason="extensiontotal", risk=risk)
            return ScanStatus.BLOCKED_RISK
        return ScanStatus.CLEAN

    def is_downloadable(self, extension_id):
        return self.check(extension_id) in DOWNLOADABLE
