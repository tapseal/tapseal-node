# Development, builds and releases

Current candidate: `1.4.1-node-only.1`. This is the node-only distribution. It retains Mainnet lot verification, the matching console, monitoring, peer checks and proof searches. Public transaction/owner/relay services and their scripts/tests are removed. The local API always applies home protections and opens the chain database read-only. It is not a deployment package for the public service.

## Verify and build

With Node 22, Python 3.10+ and npm:

```bash
python3 scripts/verify.py
python3 softnode/build-release.py
```

Tests use synthetic fixtures; no real BTC transaction is made. Check the actual hosted CI result after pushing. The workflow covers Ubuntu/macOS and pins its action revisions; inclusion of a workflow is not evidence it passed. Dependency audit results depend on the advisory database at execution time.

`artifacts/` contains the unpacked runtime, `tapseal-node-1.4.1-node-only.1.tar.gz`, its SHA-256 file and pinned `install.sh`. The runtime has a node console rather than the public website. SOURCE.json records source hashes. Ordering, timestamps, permissions and gzip metadata are normalized. Identical input and SOURCE_DATE_EPOCH produce repeatable local archives; cross-platform native dependency reproducibility is a separate concern.

## Publish

Review the source, tests, diff and credential guard. Preserve copyright, MIT and third-party notices. Never commit node_modules, production environment/config, SQLite files, logs, watchlists or private keys. Fixture keys must never hold value. Commit the source first, tag the exact reviewed commit, then attach/build that source's release artifacts. Do not overwrite a version with different bytes.

The website and GitHub source are separate publications. Upload the archive, checksum and pinned installer together to the website only after verification. Do not claim an updated website download just because main changed. No release-signing key or independent publisher authentication is implemented; a checksum delivered with a compromised bootstrap is not independent provenance.

Protocol cutovers are not ordinary UI updates. Mainnet lot-v1 activation must agree with the full server/indexer and participating clients. Do not alter an existing activation or legacy token history to make a launch work. See [LOT-V1](LOT-V1.md).

## Repository refresh

Use a clean replacement of the tracked source tree on the existing `main` branch, with a remote backup branch first. A normal new commit preserves recovery and the same repository URL; it avoids breaking website/install links or losing issues/tags. Do not force-push or delete the repository to make the files look clean. Verify existing release/download links separately before removing old assets.
