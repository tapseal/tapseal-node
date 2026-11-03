#!/bin/bash
# Install this node-only checkout as the current user. No server deployment.
set -euo pipefail
[ "$(id -u)" != 0 ] || { echo 'Use your regular user account, without sudo.'; exit 1; }
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
python3 scripts/verify.py
python3 softnode/build-release.py
VERSION=1.4.1-node-only.1
if [ -x "$HOME/.local/bin/tapseal-node" ]; then
 "$HOME/.local/bin/tapseal-node" service remove
fi
bash "artifacts/tapseal-node-$VERSION/install.sh"
"$HOME/.local/bin/tapseal-node" service install
"$HOME/.local/bin/tapseal-node" --version
printf '\nCheck startup: ~/.local/bin/tapseal-node status\nOpen http://localhost:8090\n'
