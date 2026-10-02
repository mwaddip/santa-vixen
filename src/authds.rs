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
//! ## The operations this arm grades
//!
//! This arm grades **arkadianet's public AVL surface**, not the underlying
//! `ergo_avltree_rust` crate — driving that directly would measure the
//! dependency rather than the node, the same reasoning that keeps blitzen-eni
//! off `avl_prove` (contract §6). `AvlVerifier` reports the old/looked-up value
//! for every operation the verify corpus uses:
//!
//! | Vector op | arkadianet method | reports |
//! |---|---|---|
//! | `Lookup` | `lookup` | the looked-up value |
//! | `Insert` | `insert` | nothing — the corpus expects `value: null` |
//! | `Remove` | `remove_returning_value` | the removed value |
//! | `Update` | `update` | the old value |
//! | `InsertOrUpdate` | `insert_or_update` | the old value (null if the key was new) |
//!
//! `update` and `insert_or_update` gained their `Result<Option<Vec<u8>>, ()>`
//! return in arkadianet #276; before that they returned unit, so the seven
//! entries that use them were declared `not-implemented` for the whole entry
//! rather than emit a `value: null` the corpus would read as a false divergence.
//! They are graded now — all 37 `avl_verify` entries are.
//!
//! Two operations arkadianet can now also report are left out of `REPORTABLE`
//! because no verify entry uses them yet — `remove_if_exists` and
//! `update_long_by` (both `Result<Option<Vec<u8>>, ()>`); adding an untested arm
//! would be building against the unbuilt, and it is one line when a vector lands.
//! The only op arkadianet genuinely cannot report is `UnknownModification` (no
//! method); no current verify entry uses it either. An entry carrying any op
//! outside `REPORTABLE` is declared `not-implemented` for the whole entry — a
//! blue growth-ledger cell naming a real API gap (contract §4), never coal, never
//! a fabricated verdict. Emitting a guessed `value: null` instead would
//! manufacture reds from the adapter's blindness, not from anything arkadianet
//! computes wrong.

use ergo_sigma::avl::AvlVerifier;
use serde_json::Value as J;

use crate::sval;

/// Operations whose result arkadianet's wrapper can report faithfully.
const REPORTABLE: [&str; 5] = ["Lookup", "Insert", "Remove", "Update", "InsertOrUpdate"];

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
            // The corpus expects value: null for an Insert — a new key has no old value.
            let value = sval::hex_decode(op["value_hex"].as_str().ok_or(())?).map_err(|_| ())?;
            v.insert(&key, &value).map(|_| None)
        }
        "Update" => {
            // Returns the old value the key held (the corpus expects it).
            let value = sval::hex_decode(op["value_hex"].as_str().ok_or(())?).map_err(|_| ())?;
            v.update(&key, &value)
        }
        "InsertOrUpdate" => {
            // Returns the old value if the key existed, null if it was new.
            let value = sval::hex_decode(op["value_hex"].as_str().ok_or(())?).map_err(|_| ())?;
            v.insert_or_update(&key, &value)
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
    // The contract's operation-count bounds (null = unbounded), passed to the verifier as the
    // oracle passes them to scrypto's BatchAVLVerifier: a proof padded past the node count they
    // allow is rejected at construction.
    let max_num_operations = settings["max_num_operations"].as_u64().map(|v| v as usize);
    let max_deletes = settings["max_deletes"].as_u64().map(|v| v as usize);

    let digest = sval::hex_decode(
        payload["starting_digest_hex"].as_str().ok_or("payload.starting_digest_hex missing")?,
    )
    .map_err(|e| format!("starting_digest_hex: {e:?}"))?;
    let proof = sval::hex_decode(payload["proof_hex"].as_str().ok_or("payload.proof_hex missing")?)
        .map_err(|e| format!("proof_hex: {e:?}"))?;
    let ops = payload["operations"].as_array().ok_or("payload.operations missing")?;

    // Level 1 — did a verifier build AND produce an initial digest, before any
    // operation ran. A clean crate-side rejection is `false`, not an error.
    let mut verifier = match AvlVerifier::new(&digest, &proof, key_length, value_length_opt, max_num_operations, max_deletes) {
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
