# Third-party software and provenance

This repository distributes TAPSEAL source supplied for this project and subsequent changes, with the MIT license for project-owned code. Existing source attribution and compatibility-test references are retained. The project license does not relicense third-party dependencies or grant trademark rights.

Node dependencies (including bitcoinjs-lib, better-sqlite3, Express, ipaddr.js and cryptography libraries) are obtained through npm using backend/api/package-lock.json. Their package licenses/notices remain authoritative; retain those notices if redistributing dependencies or images. Dependency license metadata is available in the lockfile and installed package LICENSE files. Native transitive components may have their own notices.

Python runtime code uses the standard library. Tests contain synthetic signing keys and transaction vectors, clearly for tests only. No live wallets or operator configurations belong in this repository.

The supplied project had no top-level license. This release adds MIT for code the project is entitled to license. Maintainers must verify any externally contributed/copied code's provenance before public release; this preparation is not a chain-of-title audit. Do not delete required third-party attribution to make the protocol appear original.
