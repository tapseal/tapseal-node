# Contributing

Open focused issues and pull requests with the trigger, resulting behavior, relevant tests and trust/security implications. Run the README test suites. Never commit generated dependencies, real keys, databases, configs, watchlists, logs or secret endpoints. Synthetic fixture keys are unsafe for real funds.

Changes to wire rules, supply/mint behavior, seal commitments or fork handling require explicit compatibility discussion and vectors across the Python and JavaScript implementations. Do not quietly change the legacy seal root into a full-ledger commitment.

Include tests that demonstrate meaningful behavior, especially persistence/reorg handling and transaction safety. Platform service changes need tests on their actual operating systems. No contributor agreement is included; contributions are expected under this project's MIT license for code you can license.

Report exploitable security issues privately using SECURITY.md, rather than a public issue.
