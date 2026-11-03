# Install your local node

Use the source-build commands in the root README. They verify the checkout, build a versioned archive, install locked dependencies, and preserve existing user data. GitHub must contain this release before cloning it provides these features. Do not paste production secrets into Git or shell commands.

## New installation

After the installer completes:

```bash
~/.local/bin/tapseal-node --version
~/.local/bin/tapseal-node network list
~/.local/bin/tapseal-node service install
~/.local/bin/tapseal-node status
```

Expected version: `1.4.1-node-only.1`. New installations default to the Mainnet seed. Open http://localhost:8090 . Wait for indexing to catch up; it can take time and API rate limits can slow it down. A blank block while the first request completes is not a balance.

## Existing Testnet installation

The update deliberately keeps your previous network. First check:

```bash
~/.local/bin/tapseal-node network list
```

If Mainnet says “not configured”, create it:

```bash
~/.local/bin/tapseal-node network configure mainnet --from https://tapseal.xyz/mainnet
```

If it is already configured, skip that command. Then:

```bash
~/.local/bin/tapseal-node network use mainnet
~/.local/bin/tapseal-node network list
~/.local/bin/tapseal-node status
```

A running supervisor queues the switch and restarts its children. Otherwise it selects Mainnet for the next start. Testnet remains saved in its separate profile/database. The Mainnet-focused interface does not delete Testnet data.

## Background operation

On macOS a LaunchAgent starts after you log in. Keep the computer awake; closing the browser/Terminal is okay. On Linux use the user service described in [Server operation](SERVER.md). Installation, loading and synchronization are different states: check `status` after service installation. Do not run another foreground node on the same profile/port while its service is running.

## What should I do next?

Check Mainnet and synchronization in the console. Add an address to the local watchlist if desired; never enter a seed phrase. For proof claims, read [Mint worker](MINT-WORKER.md). You can operate a useful monitoring node without paying or minting anything.
