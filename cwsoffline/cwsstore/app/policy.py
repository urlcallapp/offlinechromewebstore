"""Pure offline Chrome policy generation. No device changes or remote lookups."""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ID = re.compile(r"[a-p]{32}\Z")
MODES = {"allowed", "blocked", "normal_installed", "force_installed"}
DOCS = [
    "https://support.google.com/chrome/a/answer/9867568?hl=en",
    "https://support.google.com/chrome/a/answer/7532015",
    "https://support.google.com/chrome/a/answer/7517525",
]


def validate_base_url(value):
    if not isinstance(value, str) or any(c.isspace() or c in '\\"<>?#' for c in value):
        raise ValueError("base_url must be an explicit HTTP(S) origin without query or fragment")
    try:
        url = urlsplit(value)
        _ = url.port
    except ValueError as exc:
        raise ValueError("Invalid base_url") from exc
    if (url.scheme not in {"http", "https"} or not url.hostname or
            url.username is not None or url.password is not None or url.path not in {"", "/"}):
        raise ValueError("base_url must be an HTTP(S) origin, without credentials or path")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", url.hostname):
            raise ValueError("Invalid store hostname")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in url.hostname.split(".")):
            raise ValueError("Invalid store hostname")
    else:
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError("Use a client-reachable unicast store address")
    if url.hostname in {"0.0.0.0", "::", "localhost", "127.0.0.1", "::1"}:
        raise ValueError("Use a store hostname reachable by managed clients, not a bind/loopback address")
    return value.rstrip("/")


def generate_policy(spec, catalog, blocked_ids=()):
    """Return reviewable exports, requiring every administrative choice explicitly."""
    if not isinstance(spec, dict) or set(spec) - {"base_url", "default_mode", "extensions", "blocked_install_message"}:
        raise ValueError("Unknown policy fields")
    base_url = validate_base_url(spec.get("base_url"))
    default = spec.get("default_mode")
    if default not in {"allowed", "blocked"}:
        raise ValueError("default_mode must explicitly be allowed or blocked")
    assignments = spec.get("extensions")
    if not isinstance(assignments, dict) or not assignments or len(assignments) > 1000:
        raise ValueError("Select between 1 and 1000 extensions")
    message = spec.get("blocked_install_message", "")
    if not isinstance(message, str) or len(message) > 1000:
        raise ValueError("blocked_install_message must be a string of at most 1000 characters")
    available = {entry["extension_id"] for entry in catalog}
    if any(not isinstance(ext_id, str) or not ID.fullmatch(ext_id) for ext_id in blocked_ids):
        raise ValueError("Blocklist contains invalid extension IDs")
    blocked = set(blocked_ids)
    settings = {"*": {"installation_mode": default}}
    if message:
        settings["*"]["blocked_install_message"] = message
    for ext_id, mode in sorted(assignments.items()):
        if not isinstance(ext_id, str) or not ID.fullmatch(ext_id) or not isinstance(mode, str) or mode not in MODES:
            raise ValueError("Each extension needs a valid Chrome ID and supported installation mode")
        if mode != "blocked" and (ext_id not in available or ext_id in blocked):
            raise ValueError(f"Extension {ext_id} is missing or blocked; it cannot be allowed or installed")
        settings[ext_id] = {"installation_mode": mode}
        if mode in {"normal_installed", "force_installed"}:
            settings[ext_id].update(update_url=base_url + "/crx", override_update_url=True)
    # A blocklist decision must win even when the wildcard allows other extensions.
    for ext_id in sorted(blocked):
        if isinstance(ext_id, str) and ID.fullmatch(ext_id):
            settings[ext_id] = {"installation_mode": "blocked"}
    allowlist = sorted(key for key, val in settings.items()
                       if key != "*" and val["installation_mode"] != "blocked")
    warnings = [
        "Review and merge with existing enterprise policy before deployment. ExtensionSettings overrides legacy extension policies.",
        "Allowed means permitted, not installed. It does not bypass platform restrictions on off-store installation.",
        "Self-hosted automatic installation on Windows requires eligible managed devices (for example AD domain joined); verify Chrome platform requirements.",
        "Test install and subsequent update on managed Chrome, then inspect chrome://policy. This export does not apply policies.",
        "Blocking is not removal. No removed mode or automatic uninstall is generated.",
    ]
    if base_url.startswith("http:"):
        warnings.append("HTTP does not protect CRX transport. Prefer HTTPS with a certificate trusted by managed clients.")
    return {
        "extension_settings": settings,
        "gpo_extension_settings": json.dumps(settings, separators=(",", ":"), ensure_ascii=True),
        "linux_managed_policy": {"ExtensionSettings": settings},
        # Reference only: do not deploy alongside ExtensionSettings as another policy strategy.
        "extension_allowlist": allowlist,
        "store_url": base_url,
        "warnings": warnings,
        "documentation": DOCS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, help="Reviewed policy selection JSON")
    parser.add_argument("--catalog", required=True, help="Local extensions_info.json")
    parser.add_argument("--blocklist", required=True, help="Local malicious_extensions.json (use [] if none)")
    parser.add_argument("--format", choices=("bundle", "gpo", "linux", "allowlist"), default="bundle")
    args = parser.parse_args()
    try:
        spec, catalog, blocked = [json.loads(Path(path).read_text()) for path in
                                  (args.spec, args.catalog, args.blocklist)]
        if not isinstance(catalog, list) or not isinstance(blocked, list):
            raise ValueError("Catalog and blocklist must be JSON arrays")
        blocked = [item["id"] if isinstance(item, dict) else item for item in blocked]
        result = generate_policy(spec, catalog, blocked)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Policy generation refused: {exc}\n")
    if args.format == "gpo":
        print(result["gpo_extension_settings"])
    else:
        key = {"linux": "linux_managed_policy", "allowlist": "extension_allowlist"}.get(args.format)
        print(json.dumps(result[key] if key else result, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
