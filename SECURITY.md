# Security policy and boundaries

Experimental Mainnet/Testnet software; Mainnet uses real BTC. This node-only repository has no transaction builders, owner-management service, signed-pass issuer, wallet signing endpoint, transaction-preview service or Bitcoin broadcast handler. The public launch/mint website and its deployment code are separate.

The local API opens the chain database read-only. The Python indexer is its chain-state writer. All transaction mutations are unconditionally refused, including in RPC/full mode and with HOME_NODE=false. Local watchlists, proof-search settings, profile-switch requests and bounded peer check-ins are the intended separate mutations. They do not move coins or issue tokens.

Home Host/origin/CSP protections are always installed. Private local controls also require loopback request checks and a custom header. Keep port 8090 bound to loopback. Default local files are private but not encrypted. A compromised OS/user account can read them and alter the program.

Light mode depends on external block sources for availability and chain view; supported integrity checks are not full Bitcoin consensus validation. Full mode depends on the configured Bitcoin RPC. Peer observations are unauthenticated, not validator votes or proof of reward eligibility. Seal roots do not commit the complete ledger. Remote peer transport rejects reserved/private addresses and redirects and bounds responses; this does not prove absence of SSRF/DoS bugs.

The opt-in worker hashes public owner-bound proof data, pauses when complete, and neither holds spending keys nor signs/broadcasts transactions. A proof is not Bitcoin mining or independent node-service attestation. Discounts require confirmed on-chain rules, not merely running a node.

Protocol reference code and tests include encoding, cryptographic primitives, synthetic fixture keys and historical-signature verification so the node can replay real history. They are not a production signing service. Never fund fixture keys. Never publish production .env/node.json files, wallets, watchlists, RPC credentials, logs or databases.

Dependencies are locked but native/npm install scripts execute during installation. Archive hashes pin bytes, not an independently authenticated publisher; release signing is not implemented. Source guards are heuristic, tests are scoped, and this is not an independent security audit.

Do not report secrets or unpatched exploit details in a public issue. Use GitHub private vulnerability reporting if the maintainer has enabled it; otherwise ask for a private reporting channel without posting the exploit. No private endpoint or response SLA is promised.
