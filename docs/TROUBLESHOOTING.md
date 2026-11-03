# Troubleshooting

Always start with:

```bash
~/.local/bin/tapseal-node --version
~/.local/bin/tapseal-node network list
~/.local/bin/tapseal-node status
```

Before sharing logs, remove private RPC URLs/credentials and personal wallet information. Do not post node.json, environment files, watchlists or databases.

## macOS bootstrap failed: 5

The plist may be valid while launchd refuses to load it. Do not run the home installer or service as root. Run from your logged-in Mac terminal:

```bash
launchctl bootout "gui/$(id -u)/xyz.tapseal.node" 2>/dev/null || true
plutil -lint "$HOME/Library/LaunchAgents/xyz.tapseal.node.plist"
launchctl enable "gui/$(id -u)/xyz.tapseal.node"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/xyz.tapseal.node.plist"
launchctl kickstart "gui/$(id -u)/xyz.tapseal.node"
~/.local/bin/tapseal-node status
```

If bootstrap still fails, inspect without deleting data:

```bash
launchctl print "gui/$(id -u)/xyz.tapseal.node"
ls -ld "$HOME/Library/LaunchAgents"
ls -l "$HOME/Library/LaunchAgents/xyz.tapseal.node.plist"
tail -n 40 ~/.tapseal/logs/service.log
```

Version rc.2 enables the launchd job before bootstrap and exits with an error if loading fails. “Service loaded” does not promise the child API is ready or synchronized.

## Connection refused on 8090

The API is not listening yet or the supervisor exited. Check logs and launchd/systemd status. Allow startup to complete, then retry status. For foreground diagnosis, remove the service first, run `~/.local/bin/tapseal-node start`, read the first error and stop it with Ctrl-C. Do not run duplicate writers.

## Still shows Testnet3

Updating retains your active network. Follow [Quick start](QUICKSTART.md) to configure Mainnet only if missing, then use it. A historical log line is not the current status. Refresh the console with Cmd-Shift-R on Mac.

## HTTP 429 / DNS error

429 means the external block API is rate-limiting requests. DNS errors mean its hostname could not be resolved. Do not repeatedly restart or delete progress; the database persists completed work. Check connectivity, allow retries/backoff and inspect whether indexed height advances. If persistent, an operator should choose a compatible trusted block source or Bitcoin RPC. Never insert an unknown “free RPC” credential into public source. Peer agreement does not fix missing block data.

## Activation unavailable / mismatch

The corresponding Mainnet backend must publish matching `pow-v2` and `lot-v1` metadata. Check the configured Mainnet peer and server upgrade first. Do not bypass this error, invent a cutover or clear history. See [Update and recovery](UPDATING.md).

## No eligible token / no discount

A token must support the relevant proof rules and still be open. For lot claims, your wallet needs a confirmed owner approval with remaining quota and unexpired validity. A running node alone is insufficient. No tokens should be invented just to fill the dropdown.
