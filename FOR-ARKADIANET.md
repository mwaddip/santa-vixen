# A note for Arkadianet

This repository is **Vixen**, an independent conformance runner that exercises
[`arkadianet/ergo`](https://github.com/arkadianet/ergo) against
[SANTA](https://github.com/mwaddip/santa), a cross-implementation Ergo
conformance suite. It was wired by a third party (not affiliated with
arkadianet) to help your node fine-tune its costing and validation against the
canonical reference — divergences are the deliverable, and a few are already
worth your attention. This note explains what SANTA is, how Vixen drives your
code, what it has found, and how to engage.

If you read only one finding: the in-script `AvlTree` operations inherit
`ergo_avltree_rust 0.1.1`'s **panic-on-malformed-input** behavior on an
unguarded path — a crash-on-deserialize / DoS class that upstream
[ergoplatform/ergo_avltree_rust#14](https://github.com/ergoplatform/ergo_avltree_rust/pull/14)
fixes. See [§ AvlTree](#1-avltree-panics-on-malformed-input--dos-class) below.

## What SANTA is

SANTA is a language-agnostic conformance suite for Ergo consensus, modeled on
Ethereum's [`execution-specs`](https://github.com/ethereum/execution-specs)
(the executable-spec test framework that lets geth/besu/nethermind/reth prove
consensus-equivalence). Its guiding principle is **"the wire is the spec"**: a
vector is *raw serialized bytes in → expected output out*, and expected outputs
are anchored to **canonical oracles**, never to any one implementation:

- **eval / transition** outputs (typed value + JIT cost) are blessed by the
  **JVM reference** (`sigma-state` / ergo-core) — the de-facto language spec;
- **block validity** is blessed by **the chain** (a mainnet block is valid by
  definition).

Independent runners wrap each implementation and are graded against the same
committed, JVM-blessed vectors by one shared comparator. The more independent
implementations run the same vectors, the more the vectors are worth.

## What Vixen is

Vixen is a thin adapter — `vector in → {value, cost, error} out`, blind (it
never reads the blessed `expected`); SANTA's orchestrator owns the comparison.
It wraps your published crates directly:

- **eval tier** — `ergo_ser::ergo_tree::read_ergo_tree` →
  `ergo_sigma::evaluator` evaluation under a pinned canonical context, capturing
  the typed value and raw JIT cost.
- **wire tier** — `ergo_ser` byte round-trips (`read_*`/`write_*`) for
  `Constant`, `Box`, `Transaction`, `Header`, `SigmaBoolean`. Byte-round-trip
  identity is already `ergo-ser`'s own core invariant, so this tier exercises
  your serializer exactly as the node uses it.

What makes Vixen useful as a check: arkadianet shares **no consensus code** with
the JVM reference, sigma-rust, ergots, or Fleet — so where it agrees, that's
genuine independent corroboration, and where it diverges, it's a real signal.

### The one patch

arkadianet exposes no public arbitrary-root eval entry (`reduce_expr*` coerce
the root to `SigmaBoolean`; `eval_to_value` is `#[cfg(test)]`). Vixen therefore
applies a single **additive, consensus-inert** patch at build time
(`patches/0001-conformance-eval-hook.patch`): one new module
(`ergo_sigma::evaluator::conformance::eval_to_value_with_cost`) plus a one-line
`pub mod` declaration. It changes no existing code path — it only exposes the
evaluator's own entry with the cost accumulator threaded out. **An equivalent
public hook upstreamed into arkadianet would retire the patch entirely**; we'd
welcome that.

## Current standing (2026-06-08, arkadianet `main`)

Graded by SANTA's shared comparator. Live scoreboard:
<https://mwaddip.github.io/santa/>.

| tier / slice | value | cost |
|---|---|---|
| eval v5/spec | 1585 / 1609 | 1444 / 1585 |
| eval v5/authored | 76 / 98 | 44 / 76 |
| eval v6/spec | 209 / 243 | 208 / 209 |
| eval v6/authored | 50 / 111 | 38 / 50 |
| wire v5/vendored | 210 / 213 (round-trip) | — |

The v5/spec slice (the cumulative mainnet method surface) is the broadest:
~98.5% on value, ~91% on cost. The authored slices concentrate the
gap-filler / degenerate-edge vectors, so they surface the most divergence —
which is their job.

## Findings worth your attention

Grouped and actionable. These are Vixen-graded; SANTA's `santa-check` is the
canonical verdict and agrees class-for-class. All are about the build at the
pinned rev.

### 1. AvlTree panics on malformed input — DoS class

In-script `AvlTree` operations (`get`/`contains`/`insert`/`update`/`remove`)
route through `ergo_sigma::avl`, which wraps **crates.io `ergo_avltree_rust =
"0.1.1"`**. That release `.unwrap()`/`assert!`-panics on several malformed
inputs instead of returning an error:

- empty / truncated / garbage proof bytes → slice-bounds or `stack.pop().unwrap()`
  panic during proof-graph reconstruction;
- an operation value whose length ≠ the tree's fixed value length → an
  `assert!` panic in the modify path.

The digest-mode block-apply path (`ergo-state::digest_apply`) already wraps
verifier construction in `catch_unwind` and uses `value_length = None`, so it is
insulated. **The in-script evaluation path is not** — there is no `catch_unwind`
in `ergo-sigma`'s `avl.rs`, nor (we checked) in `ergo-validation`'s script path,
the mempool, sync, or the node action loop. Whether tokio task-supervision
contains the panic before a thread/process boundary is worth confirming on your
side; through validation it is uncaught.

This is a known upstream class, and the fix exists:
[ergoplatform/ergo_avltree_rust#14](https://github.com/ergoplatform/ergo_avltree_rust/pull/14)
("return Err on malformed proofs and out-of-range params instead of panicking")
honors the crate's existing `Result`/`ensure!` contract at exactly these sites.
The [mwaddip fork](https://github.com/mwaddip/ergo_avltree_rust) already carries
it, and [`ergo-node-rust`](https://github.com/mwaddip/ergo-node-rust) pins that
fork for this reason.

**We ran the experiment** (the `avltree-fork` branch of this repo redirects your
transitive `ergo_avltree_rust` to the fork via `[patch.crates-io]`, nothing else
changed):

- **All 10 in-script avltree panics are eliminated** — crash → graceful `Err`,
  which your `avl.rs` already maps to its own error type.
- **3 of the 10 then match the JVM** outright.
- **7 become clean, non-panicking outcomes that still diverge** — the panic was
  masking a second, semantic layer: arkadianet maps an avltree-op failure to
  `errored` where the JVM returns `false` / `Option None` (e.g. `contains` on a
  bad/empty/truncated proof), and returns a value where the JVM `errored` (e.g.
  `insert` with a wrong-length value).

Two separable asks: **(a)** move to the fork (or bump once #14 lands and ships)
to close the DoS surface; **(b)** then reconcile the 7 semantic cases against
the JVM. The exact entries are in `vectors/eval/**/AvlTree.bad_proof_bytes*` and
`AvlTree.per_op_failure*` in the SANTA repo.

### 2. Long division `i64::MIN / -1` panics

`Long` division at `ergo-sigma/src/evaluator/opcodes/arithmetic.rs` performs a
raw `/` that panics on `i64::MIN / -1` ("attempt to divide with overflow" —
Rust panics on division overflow regardless of build profile). The JVM-blessed
expected for this case is **`errored`** — so both agree it is an error; the
divergence is that arkadianet *panics* instead of returning the error cleanly. A
checked/guarded division closes it. (Entry: `Long_methods_equivalence ::
(-9223372036854775808,-1)`.)

### 3. Numeric overflow accepted where the JVM rejects

~73 eval entries where arithmetic / collection-fold paths **wrap** on overflow
and return a value, while the JVM rejects (`errored`). Example:
`Coll.fold` accumulating past `Int.MaxValue` returns `-2147483648` where the JVM
throws. Concentrated in `Int`/`Long`/`BigInt`/`*_6.0_methods` equivalence
vectors.

### 4. Nested-collection constant wire encoding

3 wire-tier coals, one root cause: re-serializing a deeply-nested collection
constant, `ergo-ser`'s type writer emits the **compressed nested-`Coll` prefix
(`0x18…`)** where the JVM canonical form is the general **`0x0c 0x0c…`**
encoding (`Constant.json` `coll_62/63/69`). Your *box* path is immune (candidate
register bytes are preserved verbatim); it's the standalone constant type-writer
that normalizes differently. Consensus-relevant in principle, since constant
bytes feed `boxId`.

### 5. `SContext.lastBlockUtxoRootHash` property arm missing

The `(typeId 101, methodId 9)` PropertyCall (`CONTEXT.LastBlockUtxoRootHash` as
a method) has no arm in `evaluator/opcodes/property_call.rs` (the `0xA6` opcode
form *is* implemented), so the property form evaluates to `errored` where the
JVM returns the dummy `AvlTree`.

### 6. No `SHeader` value carrier in the wire reader

`Header.property_accessors` and `Global.serialize(Box/Header)` entries error
because `ergo_ser::sigma_value::read_value` declines `SHeader` (and the value
layer has no `Header` carrier). This is the impl's own ingestion verdict, not a
mis-evaluation of the accessors — described accurately, it's "no `SHeader` value
carrier," not "Header accessors compute wrong."

## References

- **SANTA** — <https://github.com/mwaddip/santa> (start with `SPEC.md` +
  `BOOTSTRAP.md`)
- **Runner contracts** (what a runner emits — frozen for eval/wire):
  - eval: [`docs/contract/runner-contract.md`](https://github.com/mwaddip/santa/blob/main/docs/contract/runner-contract.md)
  - wire: [`docs/contract/runner-contract-wire.md`](https://github.com/mwaddip/santa/blob/main/docs/contract/runner-contract-wire.md)
  - integration (how a runner is discovered + run): [`docs/contract/runner-integration.md`](https://github.com/mwaddip/santa/blob/main/docs/contract/runner-integration.md)
- **This runner** — `main` is `vixen` (crates.io avltree); `avltree-fork` is
  `vixen-avltree-fork` (the fork experiment above). See `README.md`.
- **avltree fix** — PR <https://github.com/ergoplatform/ergo_avltree_rust/pull/14>
  · fork <https://github.com/mwaddip/ergo_avltree_rust>
- **Prior art for the fork pin** — <https://github.com/mwaddip/ergo-node-rust>
- **The model** — <https://github.com/ethereum/execution-specs>

## How to engage

SANTA is meant to be community-owned conformance ground, and the wider design is
still taking shape, so **a conversation beats a big PR** — an issue on the SANTA
repo is the best entry point. You can also run Vixen yourself: it self-provisions
its toolchain (`mise`), and `santa-run <impl-path> <vectors-dir> <out-dir>`
emits actuals, or `cargo run -- <vectors-dir>` self-compares against the blessed
expected for a quick local loop (see `README.md`). The eval and wire result
shapes are frozen; the block and transaction tiers are still being designed, and
a from-scratch node like arkadianet is exactly the kind of independent
implementation the block tier most wants.
