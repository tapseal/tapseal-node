# How the node works

The supervisor starts a block indexer and a loopback API serving the node-only console. The indexer replays TAPSEAL operations into SQLite, saves its canonical block position and applies reorg rollback. Restarts resume committed progress; they are not instructions to rescan from genesis. New protocol activation or inconsistent history can require a deliberate separate-database replay.

Mainnet and Testnet3 profiles keep separate starts, databases, sources and peers. Public UI focuses on Mainnet; CLI switching remains available. A network switch does not convert coins, copy balances or merge databases.

Light mode obtains blocks from external APIs. Supported integrity checks help detect altered block data but do not enforce all Bitcoin consensus rules or independently choose the honest chain. Full/RPC mode uses the Bitcoin node's chain view. Using an independently validated Bitcoin Core node improves the source trust model; paying for a hosted RPC does not remove provider dependence.

Peer check-ins and matching seal-output roots help compare observations and diagnose divergence. They are unauthenticated, not validator votes, stake, Sybil resistance, a full-ledger commitment or proof of rewards eligibility. Matching roots at different heights are not proof of tip agreement; inspect height, hash and freshness as well.

Local wallet monitoring reads indexed TAPSEAL holdings for selected addresses and records changes. Watch data is private local state, not encrypted storage. A stale node can miss new activity; compare freshness before relying on it. There are no spending keys in the node worker.

The worker is opt-in and runs one owner-bound token proof search. A completed proof pauses work. The public claim interface separately reviews and requests a wallet signature. A closed browser does not stop an OS service, but sleeping/offline hardware cannot keep processing. Work is not Bitcoin mining and does not prove an independent operator supplied useful node service.
