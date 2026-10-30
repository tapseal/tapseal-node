# Build, provenance and publication

The project can be built without the public Next website and without downloading a prebuilt TAPSEAL archive. Source builds use Python standard-library tooling. Runtime dependency installation still fetches locked npm dependencies.

```bash
python3 softnode/build-release.py
```

Outputs under artifacts/: unpacked runtime, versioned tar.gz, SHA-256 file and checksum-pinned install.sh. The runtime includes LICENSE, SECURITY.md, THIRD-PARTY.md and SOURCE.json (hashes of source files used for this build). Tar ordering, owner/group, modes and timestamps are normalized; gzip embeds a fixed timestamp and no source filename. With identical source and SOURCE_DATE_EPOCH (default 0), repeated local builds are byte-identical. Cross-platform/Python-version repeatability and dependency-native-binary reproducibility are separate concerns and not claimed.

Never publish .env, node.json, watchlists, logs, SQLite files or node_modules. Review the actual source before making it public. Third-party source attribution must remain intact. Fixture keys are synthetic and must never hold value. Check source rights before applying MIT to externally contributed material.

The public source repository is https://github.com/tapseal/tapseal-node. The v1 baseline was verified at commit 916ea3ead84b1eabd34ca04a89cead876e995314. This hardening update still requires committing/pushing and hosted CI verification; an included workflow is not evidence that CI has passed. Keep the intended remote distinct from unrelated projects. Enable private vulnerability reporting in repository settings before public security reports are invited.

Use a tagged source commit for each published archive, publish checksums next to it, and compare the tagged source build to the distributed archive. Document any source differences. The bootstrap currently downloads from tapseal.xyz; it must be published together with the exact matching archive. Do not overwrite an existing version with different bytes. This draft version is 1.2.0-networks.1; earlier website releases may differ. No signature/key provenance mechanism is implemented; a SHA-256 next to a compromised download is not independent publisher authentication.

After source publication, add the actual public repository/tag links to the website and home console. Do not display an invented or not-yet-created GitHub repository link. Prefer a reviewed tagged release rather than asking people to execute changing scripts from main.
