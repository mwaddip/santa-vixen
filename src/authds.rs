//! authds tier — the `avl_verify` arm, over arkadianet's own AVL wrapper
//! (`ergo_sigma::avl::AvlVerifier`), per `runner-contract-authds.md`.
//!
//! Three chained dimensions (contract §4: `accepted → results → digest`, an
//! upstream miss suppressing what is downstream):
//!
//! 1. **`proof_accepted`** — did a verifier build from
//!    `payload.starting_digest_hex` + `payload.proof_hex` + `settings`, and
//!    produce an initial digest, **before any operation is performed**.
//!    `AvlVerifier::new` returns `Result<_, String>`, so a proof the crate
//!    rejects cleanly becomes `proof_accepted: false` rather than an error.
//! 2. **`results`** — one `{ok, value}` per operation, in order, length always
//!    equal to `payload.operations.len()`. Once one operation fails, every later
//!    one is emitted as `{ok: false, value: null}` **without being performed** —
//!    the verifier is poisoned and running on would be noise.
//! 3. **`new_digest_hex`** — the digest after the last operation, or `null` if
//!    any operation failed (a poisoned verifier reports no digest).
//!
//! ## Why 20 of the 50 vendored entries are `not-implemented`
//!
//! This arm grades **arkadianet's public AVL surface**, not the underlying
//! `ergo_avltree_rust` crate. Driving that crate directly would measure the
//! dependency rather than the node — the same reasoning that keeps blitzen-eni
//! off `avl_prove` (contract §6). arkadianet's `AvlVerifier` exposes only three
//! operations that can report what the corpus expects:
//!
//! | Vector op | arkadianet method | reportable? |
//! |---|---|---|
//! | `Lookup` | `lookup` → `Option<Vec<u8>>` | yes |
//! | `Insert` | `insert` → `()`; corpus expects `value: null` | yes |
//! | `Remove` | `remove_returning_value` → `Option<Vec<u8>>` | yes |
//! | `Update` | `update` → `()` — **discards the old value** | no |
//! | `InsertOrUpdate` | `insert_or_update` → `()` — discards it too | no |
//! | `RemoveIfExists` | `remove_with_presence` → `bool`, not the value | no |
//! | `UpdateLongBy` | *(no method)* | no |
//! | `UnknownModification` | *(no method)* | no |
//!
//! The corpus expects the **old/looked-up value** for `Update`,
//! `InsertOrUpdate` and `RemoveIfExists`; arkadianet's wrapper returns unit or a
//! presence flag. Recovering it with a preceding `lookup` is NOT available: in a
//! batch verifier every operation consumes proof material and advances the
//! digest, so an injected read would corrupt the very thing being graded.
//!
//! Emitting `value: null` for those would manufacture **false divergences** —
//! reds caused by the adapter's blindness rather than by anything arkadianet
//! computes wrongly. So an entry containing any non-reportable op is declared
//! `not-implemented` for the whole entry: a blue growth-ledger cell naming a
//! real API gap (contract §4), never coal, and never a fabricated verdict.
//!
//! **Consequence worth stating loudly:** the four `UnknownModification` entries
//! are exactly the four the JVM-vs-Rust `UnknownModification` finding rests on
//! (`docs/findings/authds-unknownmodification-jvm-vs-rust.md`). vixen is
//! therefore **silent** on that finding — neither confirming nor refuting it.
//! Widening `AvlVerifier` to return the operation's old value is what would let
//! SANTA grade a second independent implementation against it.
//!
//! **One setting arkadianet discards:** `AvlVerifier::new` hardcodes
//! `max_num_operations`/`max_deletes` to `None`, though the corpus declares real
//! bounds. No current vector's expectation turns on a bound being enforced, so
//! this is a latent over-accept surface rather than a graded divergence today.

use ergo_sigma::avl::AvlVerifier;
use serde_json::Value as J;

use crate::sval;

/// Operations whose result arkadianet's wrapper can report faithfully.
const REPORTABLE: [&str; 3] = ["Lookup", "Insert", "Remove"];

pub enum AuthdsOutcome {
    Verified {
        proof_accepted: bool,
        results: Vec<J>,
        new_digest_hex: Option<String>,
    },
    /// No verdict — decode/setup failure. Carries no `note`: the authds actuals
    /// schema is note-iff-panicked, stricter than chain's (contract §3).
    Errored,
    NotImplemented,
    Panicked {
        note: String,
    },
}

impl AuthdsOutcome {
    pub fn to_json(&self) -> J {
        match self {
            AuthdsOutcome::Verified { proof_accepted, results, new_digest_hex } => {
                serde_json::json!({
                    "proof_accepted": proof_accepted,
                    "results": results,
                    "new_digest_hex": new_digest_hex,
                    "error": J::Null,
                })
            }
            AuthdsOutcome::Errored => serde_json::json!({
                "proof_accepted": J::Null,
                "results": J::Null,
                "new_digest_hex": J::Null,
                "error": "errored",
            }),
            AuthdsOutcome::NotImplemented => serde_json::json!({
                "proof_accepted": J::Null,
                "results": J::Null,
                "new_digest_hex": J::Null,
                "error": "not-implemented",
            }),
            AuthdsOutcome::Panicked { note } => serde_json::json!({
                "proof_accepted": J::Null,
                "results": J::Null,
                "new_digest_hex": J::Null,
                "error": "panicked",
                "note": note,
            }),
        }
    }
}

fn result_row(ok: bool, value: Option<Vec<u8>>) -> J {
    serde_json::json!({
        "ok": ok,
        "value": match value {
            Some(v) => J::String(sval::hex_lower(&v)),
            None => J::Null,
        },
    })
}

/// A failed / unperformed operation row.
fn failed_row() -> J {
    result_row(false, None)
}

/// Perform one operation, returning the value the corpus expects on success.
fn perform(v: &mut AvlVerifier, op: &J) -> Result<Option<Vec<u8>>, ()> {
    let tag = op["tag"].as_str().ok_or(())?;
    let key = sval::hex_decode(op["key_hex"].as_str().ok_or(())?).map_err(|_| ())?;
    match tag {
        "Lookup" => v.lookup(&key),
        "Remove" => v.remove_returning_value(&key),
        "Insert" => {
            let value = sval::hex_decode(op["value_hex"].as_str().ok_or(())?).map_err(|_| ())?;
            v.insert(&key, &value).map(|_| None)
        }
        // Unreachable: entries carrying anything else are declared
        // not-implemented before we get here.
        _ => Err(()),
    }
}

fn verify(settings: &J, payload: &J) -> Result<AuthdsOutcome, String> {
    let key_length = settings["key_length"]
        .as_u64()
        .ok_or("settings.key_length missing")? as usize;
    let value_length_opt = settings["value_length"].as_u64().map(|v| v as usize);

    let digest = sval::hex_decode(
        payload["starting_digest_hex"].as_str().ok_or("payload.starting_digest_hex missing")?,
    )
    .map_err(|e| format!("starting_digest_hex: {e:?}"))?;
    let proof = sval::hex_decode(payload["proof_hex"].as_str().ok_or("payload.proof_hex missing")?)
        .map_err(|e| format!("proof_hex: {e:?}"))?;
    let ops = payload["operations"].as_array().ok_or("payload.operations missing")?;

    // Level 1 — did a verifier build AND produce an initial digest, before any
    // operation ran. A clean crate-side rejection is `false`, not an error.
    let mut verifier = match AvlVerifier::new(&digest, &proof, key_length, value_length_opt) {
        Ok(v) => v,
        Err(_) => {
            return Ok(AuthdsOutcome::Verified {
                proof_accepted: false,
                results: Vec::new(),
                new_digest_hex: None,
            })
        }
    };
    if verifier.digest().is_none() {
        return Ok(AuthdsOutcome::Verified {
            proof_accepted: false,
            results: Vec::new(),
            new_digest_hex: None,
        });
    }

    // Level 2 — one row per operation, always. After the first failure the rest
    // are emitted unperformed: the verifier is poisoned.
    let mut results = Vec::with_capacity(ops.len());
    let mut poisoned = false;
    for op in ops {
        if poisoned {
            results.push(failed_row());
            continue;
        }
        match perform(&mut verifier, op) {
            Ok(value) => results.push(result_row(true, value)),
            Err(()) => {
                poisoned = true;
                results.push(failed_row());
            }
        }
    }

    // Level 3 — a poisoned verifier reports no digest.
    let new_digest_hex = if poisoned { None } else { verifier.digest().map(|d| sval::hex_lower(&d)) };

    Ok(AuthdsOutcome::Verified { proof_accepted: true, results, new_digest_hex })
}

/// Run one authds entry. Unknown kinds and entries whose operations arkadianet
/// cannot report faithfully become `not-implemented` (contract §4's blue
/// growth-ledger cell); decode/setup failures become `errored`.
pub fn run_entry(entry: &J) -> AuthdsOutcome {
    if entry["kind"].as_str() != Some("avl_verify") {
        // `avl_prove` is out of scope for this arm (arkadianet has a prover
        // under ergo-state, but growing that arm is a separate ask), and an
        // unrecognised kind is a coverage cell, not a failure.
        return AuthdsOutcome::NotImplemented;
    }
    let ops = match entry["payload"]["operations"].as_array() {
        Some(o) => o,
        None => return AuthdsOutcome::Errored,
    };
    if !ops
        .iter()
        .all(|o| o["tag"].as_str().is_some_and(|t| REPORTABLE.contains(&t)))
    {
        return AuthdsOutcome::NotImplemented;
    }
    match verify(&entry["settings"], &entry["payload"]) {
        Ok(outcome) => outcome,
        Err(_) => AuthdsOutcome::Errored,
    }
}
