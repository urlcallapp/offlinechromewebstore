"""Mirror the recommended Chrome extensions into the artifacts directory."""
import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone

import schedule

from . import config
from .details import get_extension_details
from .download import ChromeExtensionDownloader
from .malicious import DOWNLOADABLE, MaliciousChecker, ScanStatus

logger = logging.getLogger(__name__)

class ChromeExtensionSync:
    def __init__(self, extensions_file=None, downloader=None, checker=None,
                 report_file=None):
        self.extensions_file = extensions_file or self._default_extensions_file()
        self.downloader = downloader or ChromeExtensionDownloader()
        self.checker = checker or MaliciousChecker()
        self.report_file = report_file or os.environ.get(
            "CWS_SYNC_REPORT_FILE",
            os.path.join(config.ARTIFACTS_DIR, "last_sync_report.json"),
        )

    @staticmethod
    def _default_extensions_file():
        # Prefer the configured/cwd path, fall back to the file shipped next
        # to this package so the module works from any working directory.
        if os.path.exists(config.RECOMMENDED_EXTENSIONS_FILE):
            return config.RECOMMENDED_EXTENSIONS_FILE
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "recommended_extensions.json",
        )

    def load_recommended_extensions(self):
        """Load the recommended extension list (objects with id and name)."""
        if not os.path.exists(self.extensions_file):
            logger.warning("Extensions file not found: %s", self.extensions_file)
            return []
        with open(self.extensions_file, "r") as handle:
            return json.load(handle)

    def load_specified_extensions(self):
        """Load manually specified extensions, if the file exists.

        Same format as the recommended list: objects with id/name or plain
        ID strings. Missing file means no manual additions.
        """
        path = os.environ.get("CWS_SPECIFIED_EXTENSIONS_FILE")
        if path is None:
            artifacts_dir = os.environ.get("CWS_ARTIFACTS_DIR", config.ARTIFACTS_DIR)
            path = os.path.join(artifacts_dir, "specified.json")
        if not os.path.exists(path):
            return []
        with open(path, "r") as handle:
            return json.load(handle)

    @staticmethod
    def _parse_entry(ext):
        """Normalize a source entry to {"id", "name"?, "tags", "origin"}.

        Accepted shapes, oldest to richest: a plain ID string, {"id", "name"},
        and {"id", "name"?, "description"?, "tags"?, "origin"?}. Tags are
        display taxonomy assigned when the extension is added to the store
        sources; origin is "webstore" (mirrored from the Chrome Web Store,
        the default) or "in-house" (first-party CRX placed in the artifacts
        tree directly - sync does not try to download it).
        """
        if not isinstance(ext, dict):
            return {"id": ext, "tags": [], "origin": "webstore"}
        tags = ext.get("tags")
        return {
            **ext,
            "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
            "origin": ext.get("origin") or "webstore",
        }

    def load_extensions(self):
        """Recommended extensions merged with manually specified ones.

        Manually specified entries win on ID conflicts so a custom entry can
        override the recommended one. The blocklist applies after the merge,
        so a manual entry can never resurrect a blocked ID.
        """
        merged = {}
        for ext in self.load_recommended_extensions() + self.load_specified_extensions():
            ext_id = ext["id"] if isinstance(ext, dict) else ext
            merged[ext_id] = ext
        return [self._parse_entry(ext) for ext in merged.values()]

    def _write_extension_metadata(self, mirrored_ids, in_house_ids):
        """Write display metadata for cwsbuild, scoped to known extensions.

        Only IDs that were actually mirrored or declared in-house appear, so
        metadata can never surface a blocked or removed extension downstream.
        """
        known = set(mirrored_ids) | set(in_house_ids)
        resolved = {}
        for ext in self.load_extensions():
            ext_id = ext["id"]
            if ext_id not in known:
                continue
            metadata = {"origin": ext["origin"]}
            if ext["tags"]:
                metadata["tags"] = ext["tags"]
            if ext.get("description"):
                metadata["description"] = ext["description"]
            resolved[ext_id] = metadata
        path = os.environ.get(
            "CWS_EXTENSION_METADATA_FILE",
            os.path.join(os.environ.get("CWS_ARTIFACTS_DIR", config.ARTIFACTS_DIR),
                         "extension_metadata.json"),
        )
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as handle:
                json.dump(resolved, handle, indent=4)
        except OSError as exc:
            logger.warning("Could not write extension metadata %s: %s", path, exc)

    def sync_extensions(self, force=False):
        """Mirror every extension, skipping blocked ones and scan outages.

        Returns the number of unrecovered problems (resolution failures,
        download failures and risk-scan errors). Blocked extensions are an
        intended exclusion, not a failure.
        """
        logger.info("Starting sync at %s", datetime.now())
        extensions = self.load_extensions()
        report = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "extensions": [],
        }
        failures = 0
        blocked = 0
        scan_errors = 0
        mirrored_ids = []
        in_house_ids = []

        for ext in extensions:
            extension_id = ext["id"]
            configured_name = ext.get("name")

            if ext["origin"] == "in-house":
                # First-party extension: its CRX is placed in the artifacts
                # tree directly, there is nothing to download from the store.
                in_house_ids.append(extension_id)
                report["extensions"].append(
                    {"id": extension_id, "status": "in_house"}
                )
                continue

            status = self.checker.check(extension_id)
            if status not in DOWNLOADABLE:
                report["extensions"].append(
                    {"id": extension_id, "status": status.value}
                )
                if status is ScanStatus.SCAN_ERROR:
                    scan_errors += 1
                else:
                    blocked += 1
                continue

            try:
                details = get_extension_details(extension_id, name=configured_name)
            except Exception as exc:
                logger.error("Could not resolve extension %s: %s", extension_id, exc)
                failures += 1
                report["extensions"].append(
                    {"id": extension_id, "status": "resolve_error", "error": str(exc)}
                )
                continue

            path = self.downloader.download(
                details.extension_id, details.name, details.version, force=force
            )
            if path is None:
                failures += 1
                report["extensions"].append(
                    {"id": extension_id, "status": "download_error"}
                )
            else:
                mirrored_ids.append(extension_id)
                report["extensions"].append(
                    {
                        "id": extension_id,
                        "status": status.value,
                        "version": details.version,
                        "path": path,
                    }
                )

        self.checker.malicious_list.save()
        problems = failures + scan_errors
        report["summary"] = {
            "total": len(extensions),
            "mirrored": len(mirrored_ids),
            "in_house": len(in_house_ids),
            "blocked": blocked,
            "scan_errors": scan_errors,
            "failures": failures,
        }
        self._write_extension_metadata(mirrored_ids, in_house_ids)
        self._write_report(report)
        logger.info(
            "Sync completed at %s (%d extensions, %d blocked, %d scan errors, "
            "%d failures)",
            datetime.now(),
            len(extensions),
            blocked,
            scan_errors,
            failures,
        )
        return problems

    def _write_report(self, report):
        try:
            os.makedirs(os.path.dirname(self.report_file) or ".", exist_ok=True)
            with open(self.report_file, "w") as handle:
                json.dump(report, handle, indent=4)
        except OSError as exc:
            logger.warning("Could not write sync report %s: %s", self.report_file, exc)

    def run_forever(self, force=False):
        """Run an initial sync, then re-sync on the configured interval."""
        self.sync_extensions(force=force)
        schedule.every(config.SYNC_INTERVAL_HOURS).hours.do(self.sync_extensions)
        logger.info("Sync scheduled every %d hours", config.SYNC_INTERVAL_HOURS)
        while True:
            schedule.run_pending()
            time.sleep(60)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cwssync",
        description="Mirror Chrome Web Store extensions for offline use.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single sync and exit (no scheduler).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--sync",
        action="store_true",
        help="Incremental sync: reuse already mirrored CRX files (default).",
    )
    mode.add_argument(
        "--syncall",
        action="store_true",
        help="Force re-download of every extension, even if already mirrored.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    syncer = ChromeExtensionSync()
    if args.once:
        raise SystemExit(1 if syncer.sync_extensions(force=args.syncall) else 0)
    syncer.run_forever(force=args.syncall)


if __name__ == "__main__":
    main()
