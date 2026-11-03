# Chrome update protocol notes for the /crx feed

What cwsstore implements and where the compatibility boundaries are.

## What is implemented

- `POST /crx` accepts the updatecheck request Chrome's update client sends
  (`<request><app appid="..."><updatecheck/></app></request>`) and answers
  with a `<gupdate>` response containing only the requested app IDs.
- `GET /crx` lists every mirrored extension; `GET /crx?x=id%3D<id>%26uc`
  filters like the real `clients2.google.com/service/update2/crx` endpoint.
- Responses carry `status="ok"` on both `app` and `updatecheck`, a `codebase`
  URL built from the request's own Host (so it works behind any internal
  domain) and the newest mirrored `version`.
- Unknown app IDs are omitted from the response, matching the real service's
  behavior of returning no update for unknown IDs.

## What is deliberately not implemented

- Per-version negotiation: the response always offers the newest mirrored
  version; Chrome decides whether it is newer than the installed one.
- `<packages>` hashes and sizes in the response manifest. Mirrored CRX3 files
  keep Google's own signature, which Chrome verifies independently of the
  update manifest.
- Ping/counting fields and differential updates; they are telemetry, not
  required for installs or updates.
- Multiple app IDs in one response work, but `forkhandling` and other rare
  request attributes are ignored.

## Verification status

- Covered by tests: request parsing, per-app filtering, response shape,
  codebase URL, blocklist exclusion (tests/test_cwsstore.py).
- NOT verified: an end-to-end install/update cycle inside a real Chrome
  against a live cwsstore. First field use should confirm one force-installed
  extension updating through the feed before wider rollout.
