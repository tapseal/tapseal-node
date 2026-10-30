# TAPSEAL softnode v3 security review — 2026-10-30

Scope: supplied TAPSEAL-softnode-v3 (2).zip, redesigned website, API, Python indexer, portable node and Vultr upgrade path. Patched API/CLI version: 1.1.2-security.1. Protocol remains 1.1.0-draft.1. This is a source review and local regression assessment, not an independent certification or a live host penetration test. No production deployment or token transaction was performed.

## Findings and changes

| Severity | Finding | Patch and remaining constraints |
|---|---|---|
| High | Recursive peer discovery could request internal/private services, follow redirects or resolve to private addresses | peer-http.js requires public HTTPS port 443, validates every resolved address, pins the selected address, refuses redirects and applies time/size limits. Private peer deployments are intentionally unsupported. |
| High | Peer responses and topology could exhaust memory/connections | 128 KiB response cap; bounded topology, frontier, fan-out, concurrency and deadline. Request limits and bounded rate-limit tracking added. |
| High | Express dependency tree had reported vulnerabilities | Express 4.22.3 and locked updated dependencies; production npm audits of API and frontend reported zero known vulnerabilities at review time. This does not prove vulnerability absence. |
| High, residual | Light node does not establish full Bitcoin consensus validity | Parser/PoW/coinbase/witness checks improved, but expected difficulty transitions, cumulative-work selection, UTXO/script validation and authenticated checkpoints are incomplete. Light mode stays read-only and explicitly depends on external APIs. Vultr remains on Bitcoin RPC. |
| High, residual | Existing state root commits only live seal outputs | Preserved protocol compatibility; root_scope=seal-outputs-v1 and documentation make exclusions explicit. Token parameters, supply counters, metadata and usage are not committed. Do not use matching roots as proof of complete state equality. |
| Medium, residual | Peer identities and announcements are unauthenticated and Sybil-prone | Cross-source-IP ID takeover rejected until expiry, registration caps retained and views labelled unauthenticated/reported. Same-IP spoofing and copied roots remain possible. No identity/reward/consensus guarantee. Source IP exists in memory until expiry and is not published. |
| Medium | Proxy trust could allow forged client IP | Trust limited to loopback reverse proxy; API remains loopback by default. Verify public firewall and nginx on the host. |
| Medium | Installer lacked mandatory archive integrity and safe staging | Published bootstrap pins the exact SHA-256, requires HTTPS, bounds downloads, rejects traversal/links and stages dependencies before app replacement. A compromised website can replace both bootstrap and hash: this is not signed release provenance. |
| Medium | Configuration races/permissions and network database reuse | Atomic private temporary config, restrictive permissions; separate database paths for changed network/activation. Prior data retained. |
| Medium | Service command/path injection and malformed service definitions | systemd quoting, plist XML generation, cron escaping and direct Windows task argument lists. Actual OS-specific service boots remain untested. |
| Medium | Parser accepted malformed/unbounded data | Canonical CompactSize, size/count/truncation constraints, compact target checks, duplicate/coinbase/witness checks and bounded external responses. These are integrity checks, not full consensus validation. |
| Medium | Service/application resource exposure | API deadlines/body/connection limits, preview concurrency cap and child log rotation. Vultr updater adds reversible systemd hardening. Supervisor service stdout retention remains an operator concern. |

The installer retains Testnet3, configured database, balances, block/undo history and scanner cache, credentials and scanner drop-ins. No protocol rule or root definition was silently changed. Token-ID derived-field backfill and rollback preservation from the earlier reviewed release are included. Manual rollback preserves current data by default; restoring the old ledger requires explicit --restore-ledger.

## Validation

- API: 50 tests passed, including peer mesh, announcements, mint/transfer/burn, preview and SSRF/response bounds regressions.
- Indexer: 35 tests passed; protocol: 23 tests passed. An existing socket ResourceWarning was emitted by the indexer test process; suite passed.
- Frontend: 20 tests passed; Next static build and TypeScript completed. No browser visual validation was possible in this runtime.
- Portable node: 3 security tests passed for extraction, staged-install failure retention, private config, network separation and generated service arguments.
- SQLite migration rehearsal used a real prior-version fixture, preserved ledger and scan-progress digests, tested consistent backup and automatic code/config/ledger recovery with service operations mocked.
- Staged API smoke verification is run by the Vultr installer before service replacement. Target systemd security settings and actual credentials/RPC availability require live startup checks.
- Production dependency audits reported zero known vulnerabilities for both API and frontend at review time.

Not validated here: live Vultr OS/firewall/nginx configuration, actual platform service boot, Docker image build, hardware-wallet/UniSat interaction or real broadcast. No seed/private key is needed for this deployment. Use a small Testnet3 mint/transfer after successful rollout, and inspect scanner freshness and pending coverage before wider use.

## Trust and operational limits

An external API or RPC can censor, omit or delay data. Two external sources do not guarantee independence. A seal-root match can be copied. The network map measures reported/reachable nodes, not honest independent validators. Pending mint demand is observed coverage, not a reservation or a guarantee against sold-out races. Maintain database backups and respect the paid RPC quota; scanner limits are retained rather than increased.

## Primary references

- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html): destination validation, redirects and DNS risks.
- [Bitcoin operating modes](https://developer.bitcoin.org/devguide/operating_modes.html): full validation and lighter trust models.
- [Bitcoin Core header synchronization](https://doxygen.bitcoincore.org/class_headers_sync_state.html): difficulty/work considerations beyond isolated proof-of-work checks.

See START-HERE.md for deployment and audit-live.py for read-only target checks.
