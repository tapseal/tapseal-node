# TAPSEAL Node

**Install a local TAPSEAL node — not the minting website or its server.**

This repository contains the block indexer, protocol verification, a read-only local API, wallet monitoring, the optional proof worker, and the terminal-style node console. It does not contain the public launch website, owner-management service, transaction builders, signed-pass issuer, transaction-preview service or Bitcoin transaction relay.

Current candidate: **1.4.1-node-only.1**. Mainnet uses real BTC. Running this node does not automatically earn rewards or qualify a wallet for discounted claims.

## Install on your Mac or Linux computer

Requirements: Python 3.10+, Node.js 22 (tested), npm and Git. Native SQLite dependencies may need platform build tools. Use your regular account, without sudo.

```bash
git clone https://github.com/tapseal/tapseal-node.git
cd tapseal-node
bash install.sh
```

The installer tests this checkout, builds the node-only runtime, installs it to `~/.tapseal`, and loads its background service. New installs use Mainnet; updates preserve the active network and databases. The matching Mainnet server must publish the protocol activation metadata. Check the result:

```bash
~/.local/bin/tapseal-node --version
~/.local/bin/tapseal-node network list
~/.local/bin/tapseal-node status
```

Open **http://localhost:8090**. Wait for synchronization. The service continues with the browser or terminal closed while your computer stays awake and online. On macOS it starts after login. A loaded service is not proof of current synchronization.

## What is included?

| Component | Purpose |
|---|---|
| `install.sh` | One entry point for a tested local installation |
| `softnode` | CLI, service supervisor, release builder and node-only console |
| `node/indexer` | Replay Bitcoin blocks, save progress, handle reorgs |
| `node/protocol` | Validate TAPSEAL operations and commitments against protocol rules |
| `node/local-api` | Read indexed data, local watchlists, peer observations and proof jobs |
| `docs` | Setup, updates, troubleshooting, source trust and protocol references |

The indexer must understand deploy/mint/transfer signatures and wire formats to verify history. Protocol reference fixtures and cryptographic verification code are therefore included. They are not a production wallet, signing service or owner-control API.

## Why run it?

Keep your own persistent view of TAPSEAL history, monitor selected addresses, inspect source freshness and compare peer observations. A restart resumes committed blocks. Separate Mainnet/Testnet profiles stay separate. The optional worker searches one owner-bound proof and pauses; it never signs, spends or broadcasts.

Light mode uses external block APIs and supported integrity checks; it does not fully validate Bitcoin consensus or independently choose the honest chain. Full mode indexes through a configured Bitcoin RPC. Peer check-ins are unauthenticated observations, not votes or rewards eligibility. Seal roots do not commit the full ledger. [Trust and security](SECURITY.md).

## Guides

- [Quick start and Mainnet switching](docs/QUICKSTART.md)
- [Update without losing data](docs/UPDATING.md)
- [macOS startup and rate-limit troubleshooting](docs/TROUBLESHOOTING.md)
- [Run on a private server](docs/SERVER.md)
- [Optional proof worker](docs/MINT-WORKER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build, test and release](docs/RELEASE.md)

For lot-v1 tokens, public claims cost 700 sats per 1,000 tokens; approved proof claims cost 450. Claims permit 1–10 whole lots. A valid proof plus confirmed owner approval/quota is required for the discount; merely running a node is insufficient. Claim review/signing happens on the separate public website. [Rules and activation](docs/LOT-V1.md).

MIT project code; dependency licenses remain applicable. See [LICENSE](LICENSE), [THIRD-PARTY.md](THIRD-PARTY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md). No security certification or guaranteed earnings are claimed.
