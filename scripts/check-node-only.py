#!/usr/bin/env python3
"""Distribution scope guard. Runtime capability tests remain the security evidence."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for path in ['backend','public','website','node/protocol/preview.py','node/local-api/src/psbt.js','node/local-api/src/preview.js','node/local-api/src/allowlist.js','node/local-api/src/operator-policy.js','node/local-api/src/network-gateway.js','node/local-api/scripts/allowlist.js','node/local-api/scripts/operator-allowlist.js']:
 if (root/path).exists():raise SystemExit('Not a node-only source tree: '+path)
for path in ['node/indexer/tapseal_indexer.py','node/protocol/tapseal.py','node/local-api/server.js','softnode/node-ui/index.html','install.sh']:
 if not (root/path).is_file():raise SystemExit('Missing node component: '+path)
print('Node-only distribution scope guard passed.')
