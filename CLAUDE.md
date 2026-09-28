# Merkle Mountain Range contracts

Multi-chain MMR implementations. The actively developed package is the Sui Move one in `sui/`; `aptos/` and `flow/` are ports kept for reference.

## Stack

- Sui Move, edition `2024`, package name `mmr`. Modules: `mmr` (shared object, caps, anchors, events, object-bound verifiers), `mmr_proof` (pure verifiers over a caller-supplied root/size), `mmr_utils` and `mmr_bits` (position math; hashing conventions are frozen, shared with the Aptos port).
- Tests live in `sui/tests/`; the off-chain-style prover is the `#[test_only]` module `sui/tests/mmr_prover.move`.
- `sui/scripts/mmr_ref.py` is the Python reference prover; `sui/scripts/golden.py --check tests/mmr_proof_tests.move` fails when a pinned golden constant drifts.

## Build and test

```
cd sui
sui move build --build-env testnet --lint --warnings-are-errors
sui move test --build-env testnet
sui move test --build-env testnet --coverage && sui move coverage summary
python3 scripts/golden.py --check tests/mmr_proof_tests.move && python3 scripts/mmr_ref.py
```

`--build-env testnet` is required with sui CLI 1.69+. Per-test compute meter is about 5M units; heavy matrices are chunked. The suite must stay lint clean.

## Publishing

v2 is a fresh package, not an upgrade of the v1 testnet packages (they compute wrong roots for non-perfect sizes). `Move.lock` must carry no `[env]` publish record before `sui client publish --build-env testnet`; commit the new record afterwards.

## Sui Move guidance

@~/.claude/sui-pilot/agents/sui-pilot-agent.md
