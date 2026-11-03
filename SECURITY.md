# Security policy

This is experimental Mainnet/Testnet3 software. Mainnet uses real BTC. No security certification, full-consensus validator claim or guaranteed response SLA is offered.

Before reporting: never include real private keys, seed phrases, RPC credentials, your .env/node.json files, watchlists or production database. Public addresses and fixture keys can also expose private activity; minimize reports.

Do not put an unpatched exploitable issue or secrets into a public issue. Use the repository's private vulnerability reporting channel once the maintainer has enabled it. Until such a channel is enabled, request a private contact method from the maintainer without publishing exploit details. No private contact endpoint is configured by this source package.

## Boundaries

- The home API binds to loopback by default. Do not expose it as a public wallet-management service.
- Local monitor routes require loopback origin/host/header checks; monitored addresses and history are private local JSON, not encrypted.
- External Bitcoin APIs/RPC nodes remain trusted for availability and chain views. Light mode is not full Bitcoin consensus validation.
- Peer IDs and root matches are unauthenticated. Counts are not voting power or reward eligibility.
- Remote peer transport rejects private/reserved destinations and redirects and limits resource use. This is not a guarantee against all SSRF or denial-of-service bugs.
- Bootstraps pin archive checksums, but website/bootstrap compromise can replace both. Independent signing and published key provenance are not implemented.
- Dependencies are locked; native addon/npm install scripts still execute during installation. Inspect and trust the source/dependency chain.
- Child logs rotate; service-manager stdout retention needs operator configuration.
- The transaction preview tip-race patch retains exact canonical-tip equality and bounded retries. A new block or stale indexer can still require rebuilding.

See docs/SECURITY-REVIEW-2026-10-30.md for the earlier scoped review and its unresolved limitations. That report predates some monitoring/preview changes and is not an independent audit of this full release.

## Additional hardening

See docs/SECURITY-HARDENING-V2.md for the 1.1.5-security.1 changes and evidence. Home requests are origin/Host constrained with a script-hash CSP. Duplicate supervisors are refused, watch snapshots commit atomically from a consistent DB read, upstream RPC redirects are refused and responses bounded, and CI uses immutable action commits. These protections do not authenticate peer identity, fully validate Bitcoin, sign releases, or protect a compromised user account/OS.
