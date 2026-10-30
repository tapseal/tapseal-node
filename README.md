# TAPSEAL Node

A watch-only TAPSEAL indexer, local API and terminal-style operator dashboard. Run it on your own computer, inspect the code, build it from source and compare local seal-output observations with peers.

**Experimental software. Mainnet uses BTC; Testnet3 uses test coins. Rewards: not active. This is not Bitcoin Core.**

## What it does

- Replays TAPSEAL transactions into a persistent local SQLite database and resumes stored progress.
- Displays indexed height, source lag/freshness, peer check-ins and seal-output root comparisons.
- Watches up to 10 Taproot addresses using local indexed holdings, exact token-atom amounts and added/removed seal observations.
- Keeps the latest 100 wallet alerts across restarts and monitors every 30 seconds while its background service runs.
- Provides a local node console instead of the public minting/wallet website.
- Supports a macOS LaunchAgent or Linux user service so closing Terminal/browser does not stop it. The computer must remain awake and online.

No wallet connection, seed phrase, private key, token payment or reward eligibility is required. Watched addresses are not sent to peers or an external wallet API.

## Requirements

Python 3.10+; Node.js 22+ (Node 22 used for testing); npm; an internet connection. Native SQLite dependency installation may need platform build tools if a compatible prebuilt binary is unavailable. CPU, disk and memory requirements grow with history; no fixed low-resource guarantee is made. macOS and Linux are the primary targets. Windows uses WSL; platform boot behavior needs separate validation.

## Build and install from source

From this repository's root:

```bash
python3 softnode/build-release.py
bash artifacts/tapseal-node-1.2.0-networks.1/install.sh
~/.local/bin/tapseal-node service install
~/.local/bin/tapseal-node status
```

The build itself does not download executable code. The installer installs locked npm dependencies, then initializes settings from the configured seed. Run as your regular user, without sudo. Inspect scripts before execution. Open http://localhost:8090 and add a public address to the watch-only monitor. The default seed's network/start settings are trusted inputs, not authenticated consensus checkpoints. For explicit Testnet3 settings on first installation:

```bash
bash artifacts/tapseal-node-1.2.0-networks.1/install.sh --network testnet3 --start 5221529 --peer https://tapseal.xyz
```

The seed and external block providers can change or become unavailable. Verify activation settings independently before relying on indexed results. On an existing installation, run the installer with no initialization arguments to preserve settings/data. Stop the foreground node with Ctrl+C, or remove its background service before upgrading; reinstall the service afterward. Do not start a second foreground instance alongside the background service.

```bash
~/.local/bin/tapseal-node service status
~/.local/bin/tapseal-node service remove
~/.local/bin/tapseal-node peers add https://tapseal.xyz
~/.local/bin/tapseal-node service install
```

Home data/configuration live in ~/.tapseal, separate from the checkout. TAPSEAL_HOME overrides that directory. Build archives and checksums are under artifacts/. The locked npm dependencies are not vendored. The remote installer URL is the operator's website, not automatically a GitHub Release; publication is a separate maintainer step.

## Trust and verification limits

Light mode depends on external Bitcoin block APIs. It checks some block/header/merkle/witness integrity, but does not implement full difficulty-transition validation, greatest-work selection or UTXO/script consensus validation. It refuses transaction construction/preview/broadcast. Full/RPC mode relies on your configured Bitcoin node for those checks. The home CLI permits plaintext RPC only on loopback; remote RPC requires HTTPS or a loopback SSH tunnel.

The legacy `seal-outputs-v1` root covers live seal outputs only: token counters, parameters, metadata and usage are excluded. Peer identities/check-ins are unauthenticated and can be copied. Matching reports are not proof of independent replay, complete ledger agreement or operator identity.

Wallet monitoring covers confirmed TAPSEAL seals in the indexed history, not ordinary Bitcoin balances or pending spends. Empty holdings do not prove no holdings outside that history. Removed seals can reflect a spend, reorg or replay. Alerts are local records, not desktop/email notifications. Events between scans or while offline can be missed. The service must remain running; a sleeping computer cannot monitor.

No validator rewards, staking, mining, payouts or investment returns are implemented. Read [SECURITY.md](SECURITY.md) and [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).

## Security hardening in 1.2.0-networks.1

Home requests reject unrecognized Host headers and cross-site origins, use a hash-pinned dashboard CSP, deny framing and caching, and do not reflect permissive CORS. Only one supervisor can run per node home. Remote seed fetches and authenticated RPC calls refuse redirects; upstream body sizes/timeouts are bounded. Same-height reorgs are detected without waiting for the next block. Wallet monitor snapshots use consistent DB reads and retain committed state on errors; malformed/symlinked watch files fail closed. CI actions are pinned to commit IDs and a source guard checks for high-confidence credential/runtime-file mistakes.

This is additional defense, not a certification or full Bitcoin validation. See [docs/SECURITY-HARDENING-V2.md](docs/SECURITY-HARDENING-V2.md). Existing pre-hardening watch JSON remains untouched: watch files are now scoped by network and activation height. Re-add watched public addresses after this upgrade; the old file is preserved rather than incorrectly reusing a baseline from another indexing scope. Database/index progress and node.json stay unchanged.

## Tests

One command (installs locked development dependencies, then runs isolated tests):

```bash
python3 scripts/verify.py
```

Or run the suites individually:

```bash
cd backend/api
npm ci
npm test
cd ../..
python3 -m unittest discover -s backend/protocol -p 'test_*.py'
PYTHONPATH=backend/protocol:backend/indexer python3 -m unittest discover -s backend/indexer -p 'test_*.py'
python3 -m unittest discover -s softnode -p test_security.py
```

Tests use explicitly synthetic keys/transactions; never fund the fixture keys. The CI configuration runs these suites and checks release-build repeatability. Merely including CI files does not mean hosted CI has run.

## Source layout

| Path | Purpose |
|---|---|
| backend/protocol | Protocol rules, preview and test vectors |
| backend/indexer | Block replay, persistent scanning and external block adapter |
| backend/api | Local/API routes, peer transport, transaction verification and wallet monitor |
| softnode/tapseal-node | CLI, supervisor and service definitions |
| softnode/node-ui | Home dashboard source; no public minting website |
| softnode/build-release.py | Deterministic archive builder and checksum-pinned bootstrap |
| docs | Trust model, build/release guidance and prior review notes |

## License and contributions

MIT for TAPSEAL project code; third-party dependencies retain their own licenses. See [LICENSE](LICENSE), [THIRD-PARTY.md](THIRD-PARTY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). The MIT license permits proprietary forks; changes are not required to be published. Source availability helps inspection but does not certify safety or eliminate provider trust.

## Mainnet / Testnet3 profiles

Each network uses a separate database, activation, peer list and watch file. Existing config is saved as its active profile automatically. After the public dual backend is installed:

```bash
tapseal-node network list
tapseal-node network configure mainnet
tapseal-node network use mainnet
tapseal-node network use testnet3
```

`configure` reads network/activation metadata from https://tapseal.xyz/mainnet or /testnet3, refuses a mismatched seed, and creates a read-only light profile without copying another network's RPC credentials. `use` queues a switch through the protected local API if the supervisor is running; otherwise it selects the profile for the next start. The supervisor stops its children, saves configuration and restarts itself; databases are retained. The local dashboard provides a selector for already configured profiles. No seed phrase/private key is required.

Full/RPC indexing checks the RPC's reported network before applying blocks and checks saved DB network/activation. The API rejects a mismatched stored DB network. These checks prevent accidental mixing; they do not make an untrusted provider honest or add full Bitcoin consensus validation to light mode. First sync of another network can take time. A stale/mismatched backend remains blocked for transaction preview.
