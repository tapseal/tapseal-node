# TAPSEAL compact work v2 — release candidate 1.3.0-pow-rc.2

This revision fixes RC1's oversized OP_RETURN format for the operator's Mainnet and Testnet3 endpoints. Their 80-byte probe passed script policy, while probes at 96 bytes and above failed. The installer now tests an **80-byte payload / 83-byte script** and still requires the expected missing-input rejection. No transaction is broadcast by that probe.

## Work encoding

New PoW deployments retain flag 0x08 and encode PoW version **2**, difficulty 8–28 bits, and a 6–144-block anchor lifetime. Only new, explicitly enabled tokens use work. Existing token payloads and vectors remain unchanged. Extended deployment, work mint and operator-registration encoders reject payloads above 80 bytes; compact-token allowlist builders and protocol validation enforce the same bound. Unusually large combinations of deployment/phase parameters can be refused before signing; they are not silently truncated. Legacy operations are not universally made compatible with an 80-byte policy by this change.

A mint uses extension 0x04 plus its required named-owner flag 0x01. It carries the anchor height as a protocol varint and the nonce as uint64 little endian. **The block hash is not repeated in the payload.** Indexers derive it from their canonical block table. The nonce remains a decimal string in JSON. Browser/local jobs retain the hash so clients can search the correct preimage. API builders check that this job hash is still canonical.

SHA-256 preimage, in order: ASCII `TAPSEAL/POW/v2` plus zero; ASCII network plus zero; deployment txid bytes in displayed hex order; encoded ticker; owner key (32 bytes); anchor height (uint32 LE); canonical anchor hash (32 bytes in displayed hex order); actual treasury payment (uint64 LE, zero for fair mints); lock height (uint32 LE); nonce (uint64 LE). Digest as a big-endian integer must be below `2^(256-bits)`. The anchor must be at/after deployment, strictly before the mint block, canonical, and within the configured age. A reorganisation changes or removes the anchor and invalidates its old work.

Accepted digests are consumed once, journalled in SQLite and reversed with their block on a reorganisation. Work does not mine BTC, contribute Bitcoin hash power, establish proof of independent node operation, or guarantee earnings. Powerful hardware has an advantage. Local work is opt-in, uses no spending keys, pauses after one result and never signs/broadcasts.

## Discounts without a signature in every claim

Legacy token signed passes stay unchanged. Compact PoW tokens instead use **public, confirmed, on-chain owner approvals**. A CSV row, a server signature, a peer check-in, or a work hash alone does not qualify.

1. The creator opens the existing authority-controlled allowlist price phase: price, reserved supply and expiry. Its legacy key field is retained for wire compatibility but is not an off-chain discount authorisation for compact mints.
2. A new operation, opcode **0x07**, registers one operator: ticker, next authority output index+1, owner key (32 bytes), total lifetime quota (varint), expiry (varint, uint32 block height). It must spend the token's authority seal and re-create authority. The quota must not exceed the token max in the builder. Anyone may construct an unsigned request, but Bitcoin signatures are needed to spend the authority seal.
3. A discounted work mint sets extension **0x08** along with named-owner/work flags. It carries no signed pass. The indexer checks the on-chain quota, approval expiry, active price phase, remaining reserve, used allowance, work and total supply.

Each approval or revocation is a separate owner-signed Bitcoin transaction and costs a miner fee. Wallet/key, quota and expiry are public on chain. Quotas are total lifetime allowances, not periodic resets. Setting the quota to zero revokes it once confirmed. Re-approving does not erase previously used allowance; raising a quota only adds its difference. Closing the phase or expiry stops discounted claims. A pending approval does not qualify until indexed; a pending revocation is not final until confirmed. Bitcoin transaction order decides races. Root observations still cover seal outputs only, not the full registry or ledger.

The owner UI offers a proposed 10% token unit-price discount: fixed public rate 9 atoms/sat becomes 10, or curve discount 1,000 basis points. Other fixed rates may not represent an exact 10% price reduction and are refused by that UI. Integer rounding affects small quantities. Fair mints have no token price to discount. Miner fees, seal sats and separately disclosed platform charges are not discounted. There are no automatic payouts, staking, revenue distributions or trusted proof-of-service claims.

## Activation and database safety

Both networks use an immutable future activation height, published in `/pow-policy.json` (`rules: pow-v2`) and their API status. Mainnet schedules 144 blocks after the installation's observed node tip; Testnet3 schedules 5,000. These are upgrade windows, not fixed wall-clock durations. Home nodes fetch/copy that published policy rather than choosing their own cutover; the bootstrap remains trusted configuration. Rule mismatches are shown as other-rules, not agreement.

RC1 did not install on the reported endpoints because preflight stopped. This replacement is suitable for that situation. If an older PoW policy or ledger is already present elsewhere, the installer refuses automatic reinterpretation. It does not silently convert RC1 PoW tokens. A legacy database that passed the cutover requires replay into a separate file (`tapseal-node reindex` retains the old file). Rollback refuses to install a legacy runtime over a PoW deployment. Ordinary legacy-token data is retained.

A valid Bitcoin transaction can still contain an invalid or expired token action; payments are not automatically refunded. Canonical synchronization, UTXO checks, preview, wallet review and admission checks remain enabled. Actual Vultr deployment, real-wallet browser behavior and network-wide propagation must be checked separately. This is an experimental metaprotocol change, not an independent security audit or a Bitcoin consensus upgrade.
