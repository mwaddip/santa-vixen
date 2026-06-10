# santa-vixen

**Vixen** — the [arkadianet/ergo](https://github.com/arkadianet/ergo) runner
for the [SANTA](https://github.com/mwaddip/santa) conformance suite. The
independent one: a from-scratch Rust node sharing no consensus code with the
JVM reference, sigma-rust, ergots, or Fleet.

A thin adapter per the SANTA runner contracts: vector in → blind
`{value, cost, error}` actuals out; the orchestrator owns the comparison.

> **Arkadianet maintainers:** [`FOR-ARKADIANET.md`](FOR-ARKADIANET.md) explains
> SANTA, how Vixen drives your code, the findings worth acting on (the avltree
> DoS class first), and how to engage.

```
runner.json   manifest — name/label, version v6, tiers [eval, wire], cost
              true, impl = arkadianet/ergo #main (bare branch — latest tip;
              conform records the resolved sha per run)
santa-run     entrypoint: mise self-provision → wire ../ergo to the SANTA
              checkout → apply the build-identity patch → build → emit →
              restore the checkout (EXIT trap)
mise.toml     rust 1.95.0 (matches arkadianet's rust-toolchain.toml)
patches/      the declared build-identity override (see below)
src/          main.rs (emit + self-compare modes, never-panic net)
              eval.rs (canonical context pin §2, outcome mapping §3)
              sval.rs (SValue ⇄ JSON bridge §4, both directions)
              wire.rs (byte round-trips: Constant · Box · Transaction ·
              Header · SigmaBoolean, via ergo-ser's own codecs)
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
Upstreaming it as an arkadianet PR is the intended endgame. The `impl` ref
tracks `#main` (latest tip): the patch is append-only against a stable
14-line `mod.rs`, so conflicts are rare — when main does move under it, the
runner shows ⚠️ could-not-build in the grid until the patch is rebased
(`git apply --check` against the new tip is the whole pre-flight).

## Branches: two instances (blitzen-develop/eni pattern)

Same arkadianet node, two declared build subjects:

- **`main`** — `vixen`, on crates.io `ergo_avltree_rust = "0.1.1"` (arkadianet as
  it ships). The bare-node subject; the avltree panics surface as the finding.
- **`avltree-fork`** — `vixen-avltree-fork`, adds a `[patch.crates-io]` redirect
  of arkadianet's transitive `ergo_avltree_rust` to the
  [mwaddip fork](https://github.com/mwaddip/ergo_avltree_rust) (which returns
  `Err` where crates.io panics — ergoplatform/ergo_avltree_rust#14). Shows what
  the fork resolves, on a second independent node. Override declared per
  runner-contract §3; the checkout is untouched (pure manifest line).

**avltree-fork vs main (eval, 2026-06-08):** the fork eliminates **all 10**
in-script avltree DoS panics (crash → graceful `Err`); 1 panic remains and is
unrelated (`i64::MIN / -1` in `arithmetic.rs`). Of the 10: **3 flip to nice**
(now match the JVM), **7 become clean non-panic outcomes that still diverge**
semantically — arkadianet maps avltree-op-failure to `errored` where the JVM
returns `false`/`Option None` (`contains` on a bad/empty/truncated proof), and
returns a value where the JVM `errored` (`insert` wrong-val-len). The panic was
masking a second layer of consensus-relevant divergence the fork makes gradeable.
Net: 1874→1877 nice. Wire unaffected.

## Status

- **Eval tier: live.** Standing at arkadianet `fa97cfc` (self-compare,
  2026-06-10): **2291 nice / 5 coal / 2296 entries** — up from 1874/2288 at
  `08ee11ef` after arkadianet's 36-commit conformance round (the avltree
  panic surface is now guarded node-side: outcomes grade nice; the upstream
  crate still panics internally, caught and mapped). The 5 residuals are
  reject-arm shaped: Int+Long ArithOp coercion (JVM coerces → Long,
  arkadianet errors) · Tuple.checkType_unsupported ×2 and
  Rule1012_header_size_bit / Rule1019_check_v6_type (JVM rejects, arkadianet
  accepts — the rule entries may be enforced at arkadianet's validation
  layer, which vixen's direct read_ergo_tree→eval path bypasses; layering
  question, not yet routed).
- **Wire tier: live.** Standing at `fa97cfc`: **213 / 213 clean** (the
  nested-Coll type-prefix divergence fixed upstream; was 210/213).
- **Block tier: live** (`santa-block/v1`, patch-free). First standing at
  arkadianet `fa97cfc`: **7 / 9** — both non-PoW captured blocks fully exact
  (valid + post_digest + cost), all 5 PoW/section/cost mutations reject at
  the right gate. The 2 coals are findings: `version-gate` accepted (no
  `exBlockVersion` params-blockVersion-vs-header check in arkadianet's
  block path) and `deserialize-context-111927` cost 169202 vs blessed
  170876 (digest byte-exact; the deserialize-substitution presence-charge
  class again, now at block scope). Wiring mirrors the node's own
  digest-mode flow (`process_block_digest`) re-composed from public seams —
  PoW vs own nBits → proofs-section binding → `build_utxo_changes_raw` →
  `DigestProofVerifier::apply_block_resolving_boxes` anchored at
  `parent_digest` → `DigestUtxoView` →
  `validate_full_block_parallel_with_costs`, checkpoint-free, per-entry
  fresh.
- **Transaction tier: not built yet.** Patch-free
  (`ergo-validation::validate_transaction` over a synthetic UtxoView +
  `ergo-rest-json` decode).

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
