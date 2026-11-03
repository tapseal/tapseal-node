# Update and recovery

Do not delete `~/.tapseal` to update. It contains private settings, separate network ledgers, local watch data and logs. Keep backups private; RPC credentials may be inside configuration. An older runtime may not understand new protocol history, so restoring old application code is not automatically a safe rollback.

## Source update

Use a clean clone or reviewed tagged checkout. Do not overwrite unrelated local code. After fetching the published release, run:

```bash
python3 scripts/verify.py
python3 softnode/build-release.py
~/.local/bin/tapseal-node service remove
bash artifacts/tapseal-node-1.4.0-lots-rc.2/install.sh
~/.local/bin/tapseal-node service install
~/.local/bin/tapseal-node --version
~/.local/bin/tapseal-node status
```

The dependency install is staged before replacing the application. Previous app directories are retained. Existing node settings and history remain when the installer receives no init arguments. Never pass `--force` just to update the interface.

## Website download

The website installer may be used only after its matching archive has been published by the maintainer. A GitHub source push does not update the website automatically. Download and review the HTTPS installer before running it. Check `--version` afterward; the live website may still serve an older version.

## Activation and reindex safety

Mainnet obtains its persisted PoW/lot activation from the matching configured API. A missing, mismatched or retroactive activation fails closed. If your local database passed a newly introduced activation without the rules, preserve that database and follow the CLI's explicit separate-database reindex workflow. Do not edit activation, state roots, indexed heights or SQLite rows manually. Never replace a live database with a stale backup to hide a consistency failure.

## Remove only the background service

```bash
~/.local/bin/tapseal-node service remove
```

This does not erase settings or history. Verify the service is stopped before starting a foreground diagnostic session. To resume normal operation, reinstall the service. See [Troubleshooting](TROUBLESHOOTING.md).
