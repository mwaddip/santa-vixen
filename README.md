# santa-vixen

**Vixen** — the [arkadianet/ergo](https://github.com/arkadianet/ergo) runner
for the [SANTA](https://github.com/mwaddip/santa) conformance suite. The
independent one: a from-scratch Rust node sharing no consensus code with the
JVM reference, sigma-rust, ergots, or Fleet.

A thin adapter per the SANTA runner contracts: vector in → blind
`{value, cost, error}` actuals out; the orchestrator owns the comparison.

```
runner.json   manifest — name/label, version v6, tiers [eval], cost true,
              impl pinned to arkadianet/ergo main@<sha>
santa-run     entrypoint: mise self-provision → wire ../ergo to the SANTA
              checkout → apply the build-identity patch → build → emit →
              restore the checkout (EXIT trap)
mise.toml     rust 1.95.0 (matches arkadianet's rust-toolchain.toml)
patches/      the declared build-identity override (see below)
src/          main.rs (emit + self-compare modes, never-panic net)
              eval.rs (canonical context pin §2, outcome mapping §3)
              sval.rs (SValue ⇄ JSON bridge §4, both directions)
```

## The build-identity patch (runner-contract §3)

arkadianet exposes no public arbitrary-root eval entry (its `reduce_expr*`
coerce to `SigmaBoolean`; `eval_to_value` is `#[cfg(test)]`), so the build
applies **`patches/0001-conformance-eval-hook.patch`**: one new module
(`ergo_sigma::evaluator::conformance::eval_to_value_with_cost`) plus a
one-line `pub mod` hunk. **Additive and consensus-inert** — no existing code
path changes; DeserializeContext stays arkadianet's inline production
behavior; the patch only exposes the evaluator's own entry with the cost
accumulator threaded out. Applied by `santa-run` at build time and reverted
after (the SANTA-owned checkout stays pristine for the next fetch+checkout).
Upstreaming it as an arkadianet PR is the intended endgame; the patch is
validated against the `runner.json` pin and moves with it.

## Status

- **Eval tier: live.** First full-corpus standing (self-compare, 2026-06-08,
  arkadianet `08ee11ef`): **1874 nice / 414 coal / 2288 entries**. Coal by
  class: 186 cost (NEQ-of-collections families + per-method rows) · 136
  success→errored (Header constants refused, UBI arith, AvlTree degenerate
  flags, Global.serialize Box) · 73 errored→success (numeric-method overflow
  paths accept where the JVM rejects) · 11 panicked (10 ×
  `ergo_avltree_rust 0.1.1` on malformed proofs/value-length asserts, 1 ×
  `i64::MIN / -1` divide overflow) · 5 value (tuple-register Coll[Byte]
  zeroed ×2, length 133v135 ×1, decodePoint off-curve/zero-lead ×2) · 3
  not-implemented (substConstants). All candidate impl findings — surfaced,
  not yet routed upstream.
- **Wire + transaction tiers: not built yet.** Both are patch-free
  (`ergo-ser` round-trips; `ergo-validation::validate_transaction` over a
  synthetic UtxoView + `ergo-rest-json` decode). Block tier once SANTA's
  contract for it lands.

## Standalone dev

`Cargo.toml` path-deps `../ergo/*` (the same sibling shape santa-run wires).
For a local loop:

```bash
ln -sfn ~/projects/arkadianet/ergo ~/projects/ergo   # sibling checkout, once
git -C ../ergo apply patches/0001-conformance-eval-hook.patch
cargo run --release -- ../santa/vectors/eval/v5 ../santa/vectors/eval/v6
git -C ../ergo checkout -- . && git -C ../ergo clean -fd -- ergo-sigma/src/evaluator/
```

Self-compare prints a nice/coal tally plus the first coal diffs — a dev
convenience only; `./conform`'s shared comparator is the canonical verdict.
