# Superteam submission — Solana Program Integrity for ZeroClaw

## 15-second pitch

`solana_program_integrity` lets a ZeroClaw agent verify **the exact Solana program bytes deployed on-chain before trusting a protocol**.

It follows the upgradeable-loader `Program -> ProgramData` link, hashes the deployed code region with SHA-256, reports deployment slot + upgrade authority, and compares the result to an operator-owned trusted fingerprint. Optional dual-RPC mode fails closed if two providers disagree.

This is deliberately **T0 / read-only**: no private keys, no signing, no transaction building, no submission, no filesystem access.

## Why it matters

An upgrade-authority checker answers: **who can replace this program?**

This plugin answers a different supply-chain question: **are the bytes deployed right now the exact bytes my agent/operator expects?**

That distinction matters for autonomous agents. A protocol name, website, Program ID, or even an unchanged upgrade authority does not prove the deployed binary is still the audited release.

## Judge it in 60 seconds

From the repository root:

```bash
rustup target add wasm32-wasip2
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
sha256sum target/wasm32-wasip2/release/solana_program_integrity.wasm
```

CI runs the same locked gates on every change.

## Safety properties

1. **Prompt/model input cannot choose the RPC.** Public input is limited to a canonical `program_id` and optional expected SHA-256.
2. **Operator policy beats model input.** `trusted_sha256` in jailed config takes precedence over caller input.
3. **Injection-shaped program IDs fail before I/O.** Canonical base58 and exact 32-byte decoding are required.
4. **Unknown config fails closed.** Unsupported or misspelled configuration keys are errors.
5. **RPC evidence is bounded and structurally validated.** Loader ownership/state, context slots, base64, decoded size, and ELF magic are checked.
6. **Optional independent provider agreement.** With `secondary_rpc_url`, both RPCs must agree on ProgramData address, slot, authority, length, and SHA-256.

## Verdict semantics

| Verdict | Meaning |
|---|---|
| `GREEN` | Expected hash matches **and** no upgrade authority remains. |
| `AMBER` | Hash matches but upgrade authority exists, or no trusted hash was supplied. |
| `RED` | Deployed code bytes do not match the expected fingerprint. |
| Tool failure | Evidence is malformed, incomplete, oversized, unsupported, or contradictory. |

No missing-evidence path produces `GREEN`.

## ZeroClaw fit

- Rust standalone crate
- `cdylib + rlib`
- pure host-testable core + thin WASM shim
- `tool-plugin` WIT world
- structured ZeroClaw logging
- `wasm32-wasip2`
- only `http_client` + `config_read` permissions
- committed `Cargo.lock`
- no registry mutation during bounty judging

## Scope

v0.1 intentionally supports upgradeable-loader BPF programs only. It does not claim to audit source code, prove developer identity, rate protocol economics, or move funds. Its job is narrow and composable: **bind an agent's trust decision to the exact bytes deployed on Solana.**
