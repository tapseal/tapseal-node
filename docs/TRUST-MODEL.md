# What a TAPSEAL node establishes

A local replay provides an inspectable derived view of the blocks the source supplied, from the configured activation height. It preserves local SQLite progress. It is not proof that the source supplied the greatest-work Bitcoin chain.

The light adapter checks certain data-integrity properties. It does not fully validate Bitcoin difficulty transitions, cumulative-work selection, scripts or UTXOs. Adding another external API does not establish source independence.

The seal-output root excludes token counters, parameters, metadata and usage. Peer comparisons at a common height are consistency observations only; any operator may copy them. Reports expire but have no authenticated identity or proof-of-work-service scheme. There is no validator quorum or rewards mechanism.

Wallet monitoring reads local seals and stores bounded snapshots/alerts. It is watch-only and requires no seed. A seal disappearance is not a definitive theft alert. Indexer freshness and coverage are material, as are time offline, reorgs and the 30-second sampling interval. Watchlist retention is local private JSON, not encrypted storage or a notification-delivery service.

RPC-backed transaction preview independently checks claimed inputs, simulates protocol effects and requires the indexed height/hash to equal a fresh canonical RPC tip. It retries transient mismatches with fresh snapshots within limits; it never accepts a stale snapshot as fallback. Finalized transactions require admission checks. Chain state can still change later.
