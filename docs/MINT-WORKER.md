# Optional mint worker

1. Confirm Mainnet and current synchronization in the local console.
2. Select an existing eligible token. If none exist, there is nothing to search.
3. Enter the receiving Taproot address (`bc1p…`) controlled by the wallet you will use to claim. Never enter a private key or seed phrase.
4. For a lot token choose 1,000–10,000 tokens. Payment is 450 sats per 1,000, not paid by the worker.
5. Choose a CPU target and start one search. Keep the computer awake and service running.
6. When a proof completes, copy it to https://tapseal.xyz/mining/ . Connect the same wallet, review quantity, treasury payment, seal outputs and miner fee, and explicitly sign if correct.

A lot-mode discounted claim requires both an owner-approved wallet with confirmed, unexpired, unused quota and a valid proof. Approval does not reserve supply. Work can expire; another mint can consume the remaining supply first. There is no guaranteed allocation or income. Public lot claims cost 700 sats per 1,000 and need no proof. Existing non-lot token rules may differ.

The worker never signs, broadcasts, pays or changes token rules. Running the node is useful for local history/monitoring, but is not by itself evidence that should grant an approval. Proof work is not Bitcoin mining, transaction confirmation or network consensus.
