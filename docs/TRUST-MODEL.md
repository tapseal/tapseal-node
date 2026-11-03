# Node-only trust model

See [Architecture](ARCHITECTURE.md) and [Security](../SECURITY.md). This distribution observes and verifies indexed TAPSEAL state; it does not prepare, simulate, sign or relay spending transactions. Its local UI is not the public mint service.

Light mode uses external block APIs; full/RPC mode uses a Bitcoin node's chain view. Neither mode turns peer check-ins into authenticated consensus or rewards. Inspect freshness, height/hash and source failures before relying on local balances. Persistent history and independent source choice can reduce reliance on a single website, but do not remove provider or software trust.
