# Security hardening v2 — 30 October 2026

Scope: public source baseline `916ea3ead84b1eabd34ca04a89cead876e995314` in https://github.com/tapseal/tapseal-node and its home runtime. The 64 published files were compared with the prepared source using Git blob hashes. This update is CLI/API 1.1.5-security.1. No protocol wire rules, supply/mint rules or seal-root definition change.

This is a scoped source review and regression exercise, not an independent penetration test, formal proof, chain-of-title audit, or a promise of vulnerability absence. The source update has not been deployed to the user's Mac/Vultr or pushed through this review environment. A successful public Git push does not upgrade running software.

## Findings and fixes

| Area | Finding / risk | Change and evidence |
|---|---|---|
| RPC credential boundary | Python RPC transport could follow redirects; some API provider/RPC calls lacked full response limits or timeouts | Python refuses redirects and bounds response bodies (64 MiB normal, 128 KiB errors); Node upstream helper refuses redirects, limits size, aborts slow bodies. Preview and broadcast/UTXO routes use it. Broadcast provider errors are sanitized and concurrent broadcasts capped at four. Relay transaction IDs must equal the locally computed transaction ID before success is reported. Tests cover redirect refusal, chunked-size limits and slow-body abort. Configured upstreams remain trusted data sources. |
| Home browser boundary | General home API had reflective CORS and no Host/CSP policy beyond the monitor's own existing origin checks | HOME_NODE mode constrains Host/Origin/Fetch Metadata, disables permissive CORS, pins dashboard script hashes, denies framing, caching and cross-origin resource use. Applies only when home CLI enables it; public server origin policy is separate. Tests include actual HTTP rejection of an attacker Host and cross-site Origin. These headers supplement safe DOM usage, not replace it. |
| Duplicate writers | A service and foreground supervisor could index the same DB concurrently using separate in-memory states | Exclusive per-home OS lock refuses the second supervisor. Symlinked/unowned home directories and lock-file symlinks fail closed. Home startup as root is refused. Lock exclusivity/reacquisition tested. It does not coordinate different homes manually configured to the same external DB path. |
| Chain freshness | A same-height reorg was not detected until a later block arrived | Compare stored tip against canonical RPC hash before catch-up; roll back/replay on mismatch, even with no higher block. Check returned block height/hash before applying. Tests compare replay to a fresh index and reject inconsistent blocks. One extra rate-limited tip-hash RPC check per follow cycle is required. Deep reorgs beyond retained undo still require operator recovery; no silent DB reset is added. |
| Watch state consistency | Monitor read tip/holdings separately and could leave partially updated in-memory observations after errors; persisted snapshot fields lacked strict validation | Read all watched holdings in one SQLite read transaction. Stage a cloned snapshot and commit only after validation and atomic/fsynced file replacement. Errors retain the last committed snapshot with a displayed error. Validate bounded persisted state and refuse symlink files. Snapshot validation/failure retention/restart tests pass. |
| Seed/config transport | CLI seed/peer setup could follow redirects or use insecure remote endpoints | Seed/peer reads require HTTPS 443 with no embedded credentials/query/fragment and no redirects. Local status remains HTTP loopback. Home RPC permits plaintext only on loopback; remote RPC needs HTTPS or an SSH tunnel. Config size/network/start/port validation added. Tests exercise those restrictions. |
| Supply chain / accidental disclosure | Floating CI tags and no automatic high-confidence source-secret guard | Pin checkout/setup actions to immutable commit SHAs fetched from their official repositories. Source guard blocks recognizable token/private-key patterns, runtime config/DB files, symlinks and unexpectedly large source files. It runs in CI and before release build. Dependency audit check added to CI and weekly Dependabot configuration included. These are heuristic/layered controls, not proof of secret absence or trustworthy dependencies. |

## Local validation

- 67 API tests passed, including original transaction/peer/monitor regressions and new hardening tests.
- 39 indexer tests passed, including same-height reorg and RPC response/redirect tests.
- 23 protocol tests passed; wire behavior unchanged.
- 7 portable-node/security tests passed, including installer failure retention, extraction, locking, transport and source-guard cases.
- Total: 136 tests. An existing indexer test fixture emits a socket ResourceWarning; the suite passes. This does not establish OS service or browser behavior.
- Production npm audit: zero known findings at review time. This result changes as advisories are published and does not establish vulnerability absence.
- Release archive repeatability is checked locally and in CI configuration; hosted CI results are separate and must be reviewed after pushing.
- No real signing/broadcast, authenticated adversarial network exercise, Mac launchd boot, Windows/WSL boot, Docker build, external host/firewall test or independent expert audit occurred here.

## Compatibility / rollout

This is a source update. Commit/push it, review hosted CI, then build a new immutable versioned release. Install that new release on each home node to activate the protections. Do not overwrite earlier release bytes under an old version name. The public website and managed Vultr deployment have separate upgrade paths.

Node settings and indexed DB progress remain intact. Watch files are now scoped by both network and activation height; previous network-only watch files are preserved but not silently adopted. Re-add watched addresses after upgrade. That avoids comparing holdings against a baseline from a different indexed history. Background monitoring still requires the computer awake and online. Docker loopback forwarding and OS/browser behavior need separate validation.

## Important remaining limits

1. Light mode is not full Bitcoin consensus validation. Difficulty transitions, cumulative-work selection, UTXO/script validation and authenticated checkpoints remain incomplete. External APIs can mislead, omit data or stop responding.
2. The legacy root commits only live seal outputs. Token counters/parameters/metadata/usage are excluded. Matching roots do not prove complete state equality.
3. Peer IDs/check-ins are unauthenticated and Sybil-prone. No rewards or validator quorum is implemented.
4. Bootstrap checksums are not independent signed publisher provenance. A compromised website/bootstrap can replace both archive and checksum. npm/native install scripts and runtime dependencies remain part of the supply chain.
5. The home node cannot protect a compromised user account/OS or stolen signing-wallet credentials. It does not hold wallet signing keys, but optional RPC/allowlist credentials still need private handling.
6. Source secret checks cover this reviewed snapshot and recognizable patterns, not all Git history, accounts, backups, unknown credential formats or dependencies. Tokens exposed in chat/screenshots must be revoked at GitHub; changing source code does not revoke them.
7. Private vulnerability reporting, branch protection, required CI reviews and repository administrator settings require maintainer setup. Config files alone do not enforce those repository settings. Release signing/provenance is not implemented by this patch.

## References

- [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

An independent application/cryptography review remains appropriate before promoting this experimental software for real-value use.

## macOS interpreter follow-up

A user verification run on macOS failed when fixtures used Homebrew Python but protocol previews defaulted to /usr/bin/python3. The same user reported a passing verification run after explicitly selecting the Homebrew interpreter with PYTHON_BIN. The permanent fix makes verification pass sys.executable to API tests, makes the home supervisor pass its interpreter to the API, and uses PATH python3 as the standalone fallback. No SQLite permission changes or security-check bypass is introduced. A regression exercises an explicitly selected interpreter with spaces in its path. CI now includes Linux and macOS; actual hosted results still require checking after push.
