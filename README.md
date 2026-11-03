# TAPSEAL Node

Run your own local TAPSEAL indexer and monitoring console. Replay token history into a persistent database, watch Taproot holdings, and inspect synchronization and peer observations from your own computer or server.

**Release candidate: 1.4.0-lots-rc.2. Mainnet uses real BTC.** The node never needs your seed phrase or spending key. Home transaction APIs are read-only. Running a node does not automatically earn rewards, grant mint discounts, or secure Bitcoin consensus.

## Start here

| You want to… | Guide |
|---|---|
| Install on a Mac or Linux computer | [Quick start](docs/QUICKSTART.md) |
| Update without losing history | [Update and recovery](docs/UPDATING.md) |
| Keep a server running | [Server operation](docs/SERVER.md) |
| Fix startup, wrong network or rate limits | [Troubleshooting](docs/TROUBLESHOOTING.md) |
| Understand trust and node usefulness | [How it works](docs/ARCHITECTURE.md) |
| Search a discounted mint proof | [Mint worker](docs/MINT-WORKER.md) |
| Build, test and publish source | [Development and release](docs/RELEASE.md) |

## Install from reviewed source

Requirements: Python 3.10+, Node.js 22 (tested), npm, Git, internet access. Run as your regular user; **do not use sudo** for the home install. Native SQLite dependencies may need platform build tools.

```bash
git clone https://github.com/tapseal/tapseal-node.git
cd tapseal-node
python3 scripts/verify.py
python3 softnode/build-release.py
bash artifacts/tapseal-node-1.4.0-lots-rc.2/install.sh
```

For a new installation, settings are obtained from the Mainnet seed. Existing installations retain their active network and databases. See [Quick start](docs/QUICKSTART.md) before switching an existing installation.

```bash
~/.local/bin/tapseal-node service install
~/.local/bin/tapseal-node status
```

Open **http://localhost:8090**. A startup message is not proof of synchronization: inspect network, indexed height, lag and errors. Mainnet startup requires the matching server to publish `lot-v1` activation metadata. The service runs with the browser/terminal closed, while your computer stays awake and online. macOS starts it after login; Linux persistence after logout may require user lingering.

## What your node provides

- A local copy of TAPSEAL history that resumes from stored blocks after restart.
- Local address monitoring and exact token balances from that indexed history.
- Visibility into source lag, failures, seal-output roots and peer check-ins.
- Optional owner-bound proof searches for eligible tokens, without keys or automatic payments.

Light mode downloads block data from external APIs and checks supported block integrity properties. It **does not perform full Bitcoin consensus validation**. Full mode indexes through your Bitcoin RPC; Bitcoin validation depends on that Bitcoin node. Peer reports are unauthenticated, and a seal-output root is not a commitment to the complete ledger. One agreeing peer is not independent consensus. See [security boundaries](SECURITY.md).

## Main-token launch profile

The new activated `lot-v1` mode has 21M tokens and whole 1,000-token lots, 1–10 lots per claim. Public price is 700 sats/lot without a proof. Approved proof claims cost 450 sats/lot and require both a valid proof and a confirmed owner-authorized quota. Bitcoin fees and seal-output BTC are separate. No reservation, automatic reward or guaranteed return exists. Existing tokens retain their rules. [Protocol specification](docs/LOT-V1.md).

## Source layout

| Directory | Purpose |
|---|---|
| `backend/protocol` | Wire formats, commitments and token state transitions |
| `backend/indexer` | Persistent replay, RPC/block APIs and mempool scanning |
| `backend/api` | Local API, monitoring, worker policy and shared full-service code |
| `softnode` | CLI, background supervisor, release builder and node-only console |
| `docs` | Installation, operation, trust model and protocol references |

The home archive contains the node console, not the public token-launch website. Shared backend transaction code is included for reproducible verification, but home transaction routes are disabled. This repository does not contain production RPC secrets or live databases.

MIT project license; third-party licenses remain applicable. See [LICENSE](LICENSE), [THIRD-PARTY.md](THIRD-PARTY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md). Source publication is not an independent security audit. Hosted CI and real OS/wallet operation must be checked separately.
