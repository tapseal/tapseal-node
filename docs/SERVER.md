# Run on a server

Use a dedicated unprivileged operating-system account with Python 3.10+, Node 22 and npm installed. Install from reviewed source as that user, not root. Keep the console/API bound to loopback; do not open port 8090 to the internet.

On Linux with a user systemd session:

```bash
~/.local/bin/tapseal-node service install
~/.local/bin/tapseal-node status
systemctl --user status tapseal-node
journalctl --user -u tapseal-node -n 40 --no-pager
```

If the installer reports that lingering is unavailable, a server administrator can enable it for the actual node account (`loginctl enable-linger ACCOUNT`). This lets the user service survive logout/start at boot. A user systemd session must be available; do not substitute a root home installation. Other init environments use the CLI's documented fallback or a separate reviewed deployment.

To view the remote console from your own computer, tunnel it:

```bash
ssh -N -L 8090:127.0.0.1:8090 YOUR_USER@YOUR_SERVER
```

Open http://localhost:8090 . If your computer already runs a node on 8090, stop it or use a different local tunnel port for read-only viewing; origin-sensitive local controls expect their configured port.

Budget disk for indexed history and monitor CPU, memory, network traffic and API limits. Light mode still depends on external block APIs. Full mode uses your Bitcoin RPC and does not turn a home TAPSEAL node into a public mint relay. Keep RPC access private and HTTPS for remote providers. Protect configuration backups like credentials.

The release archive contains Docker files as an advanced option. Docker/Windows/WSL boot and host-origin behavior require platform validation; the native Mac/Linux service is the primary documented path. Do not expose a Docker console with a public port mapping.
