//! Vixen — the arkadianet/ergo runner for the SANTA conformance suite
//! (eval tier; wire + transaction to follow).
//!
//! Two modes — `eval::run_entry` produces actuals **blind** (never reads
//! `expected`) in both:
//!   vixen <vector.json | dir> [...]        self-compare: run each entry,
//!                                          compare vs the blessed `expected`,
//!                                          print nice/coal. Dirs recurse.
//!   vixen emit <vectors-dir> <out-dir>     emit actuals for the SANTA
//!                                          orchestrator: one actuals file per
//!                                          vector, mapping entry name →
//!                                          { value, cost, error }. No
//!                                          comparison — the orchestrator owns
//!                                          the §5 comparator.

mod block;
mod chain;
mod eval;
mod sval;
mod wire;

use serde_json::Value as J;
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => {
            if args.len() < 4 {
                eprintln!("usage: vixen emit <vectors-dir> <out-dir>");
                std::process::exit(2);
            }
            emit(Path::new(&args[2]), Path::new(&args[3]));
        }
        Some(_) => self_compare(&args[1..]),
        None => {
            eprintln!(
                "usage:\n  \
                 vixen <vector.json | dir> [...]    self-compare vs blessed expected\n  \
                 vixen emit <vectors-dir> <out-dir>  emit actuals for the SANTA orchestrator"
            );
            std::process::exit(2);
        }
    }
}

/// Extract a printable message from a caught panic payload.
fn panic_note(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// Run one entry's eval under a panic net (never-panic, contract §3): an
/// otherwise-uncaught panic becomes the `panicked` outcome (coal, message in
/// `note`) so the run continues.
fn caught_actual<F: FnOnce() -> J + std::panic::UnwindSafe>(f: F) -> J {
    match std::panic::catch_unwind(f) {
        Ok(j) => j,
        Err(p) => {
            let note = panic_note(p);
            eval::Outcome::Panicked { note: format!("panic: {note}") }.to_json()
        }
    }
}

/// The same never-panic net for block entries — the panic shape carries
/// `valid`/`post_digest` (santa-block actuals), not eval's `value`.
fn caught_actual_block<F: FnOnce() -> J + std::panic::UnwindSafe>(f: F) -> J {
    match std::panic::catch_unwind(f) {
        Ok(j) => j,
        Err(p) => {
            let note = panic_note(p);
            block::BlockOutcome::Panicked { note: format!("panic: {note}") }.to_json()
        }
    }
}

/// The chain-shaped never-panic net (santa-chain panic envelope).
fn caught_actual_chain<F: FnOnce() -> J + std::panic::UnwindSafe>(f: F) -> J {
    match std::panic::catch_unwind(f) {
        Ok(j) => j,
        Err(p) => {
            let note = panic_note(p);
            chain::ChainOutcome::Panicked { note: format!("panic: {note}") }.to_json()
        }
    }
}

/// Evaluate every entry of one vector file (blind), pairing each entry's
/// `name` with its actual JSON and the vector's blessed `expected` JSON.
/// Returns empty for a non-eval vector (wire/transaction — not wired yet).
fn run_vector_file(path: &Path) -> Vec<(String, J, J)> {
    let text = std::fs::read_to_string(path).expect("read vector file");
    let vector: J = serde_json::from_str(&text).expect("parse vector JSON");
    // Dispatch on the schema discriminator: wire entries round-trip
    // `bytes_hex` (the blessed expected IS the entry's own bytes); eval
    // entries evaluate `tree_bytes_hex` against the blessed `expected`.
    let schema = vector["schema"].as_str().unwrap_or("");
    let is_eval = schema.starts_with("santa-eval/");
    let is_wire = schema.starts_with("santa-wire/");
    let is_block = schema.starts_with("santa-block/");
    let is_chain = schema.starts_with("santa-chain/");
    if !is_eval && !is_wire && !is_block && !is_chain {
        return Vec::new();
    }
    let entries = match vector["entries"].as_array() {
        Some(e) => e,
        None => return Vec::new(),
    };
    entries
        .iter()
        .map(|entry| {
            let name = entry["name"].as_str().unwrap_or("<unnamed>").to_string();
            if is_wire {
                let kind = entry["kind"].as_str().expect("wire entry missing kind");
                let bytes_hex = entry["bytes_hex"]
                    .as_str()
                    .expect("wire entry missing bytes_hex");
                let actual = caught_actual(std::panic::AssertUnwindSafe(|| {
                    wire::run_entry(kind, bytes_hex).to_json()
                }));
                let expected = serde_json::json!({"bytes_hex": bytes_hex, "error": J::Null});
                return (name, actual, expected);
            }
            if is_chain {
                let actual = caught_actual_chain(std::panic::AssertUnwindSafe(|| {
                    chain::run_entry(entry).to_json()
                }));
                // Per-kind expected in the actuals vocabulary (value-only
                // tier; `diagnostic` never read). The voting reject arm
                // (contract amendment @ santa 7f564b8) blesses
                // expected.error == "errored" — inputs the JVM throws on.
                let expected = if entry["expected"]["error"] == "errored" {
                    // Match the runner's union errored envelope (note is
                    // stripped by the self-compare normalize, like reason).
                    serde_json::json!({
                        "nbits": J::Null, "parameters": J::Null,
                        "activated_update": J::Null, "error": "errored",
                    })
                } else {
                    match entry["kind"].as_str().unwrap_or("") {
                        "retargeting" => serde_json::json!({
                            "nbits": entry["expected"]["nbits"], "error": J::Null,
                        }),
                        _ => serde_json::json!({
                            "parameters": entry["expected"]["parameters"],
                            "activated_update": entry["expected"]["activated_update"],
                            "error": J::Null,
                        }),
                    }
                };
                return (name, actual, expected);
            }
            if is_block {
                let actual = caught_actual_block(std::panic::AssertUnwindSafe(|| {
                    block::run_entry(entry).to_json()
                }));
                // Blessed expected in the actuals vocabulary; `reason` is
                // diagnostic-only (never graded) — self-compare strips it
                // from both sides so a clean reject isn't coal'd on the
                // reject-string differing.
                let expected = serde_json::json!({
                    "valid": entry["expected"]["valid"],
                    "post_digest": entry["expected"]["post_digest"],
                    "cost": entry["expected"]["cost"],
                    "error": J::Null,
                });
                return (name, actual, expected);
            }
            let tree_hex = entry["tree_bytes_hex"]
                .as_str()
                .expect("entry missing tree_bytes_hex");
            let tree_bytes = sval::hex_decode(tree_hex).expect("bad tree_bytes_hex");
            let input = entry.get("input").filter(|v| !v.is_null());
            let inputs = entry.get("inputs").and_then(|v| v.as_array());
            let self_registers = entry.get("selfRegisters").and_then(|v| v.as_object());
            let tree_v = entry["version"]["ergoTree"].as_u64().unwrap_or(0) as u8;
            let act_v = entry["version"]["activated"].as_u64().unwrap_or(0) as u8;
            let actual = caught_actual(std::panic::AssertUnwindSafe(|| {
                eval::run_entry(&tree_bytes, input, inputs, self_registers, tree_v, act_v).to_json()
            }));
            let expected = entry["expected"].clone();
            (name, actual, expected)
        })
        .collect()
}

/// Self-compare mode: evaluate the corpus and tally nice/coal vs the blessed
/// `expected` (dev convenience; conform's comparator is the real verdict).
fn self_compare(paths: &[String]) {
    let mut files: Vec<PathBuf> = Vec::new();
    for p in paths {
        collect_vector_files(Path::new(p), &mut files);
    }
    files.sort();
    if files.is_empty() {
        eprintln!("no .json vector files found");
        std::process::exit(2);
    }

    let (mut nice, mut coal, mut total) = (0u64, 0u64, 0u64);
    let mut coal_list: Vec<(String, String, J, J)> = Vec::new();

    for f in &files {
        let short = f.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        for (name, actual, expected) in run_vector_file(f) {
            total += 1;
            // `reason` (block/tx) and `note` (chain errored) are
            // diagnostic-only — never graded; strip both for the equality
            // so a clean reject isn't coal'd on its diagnostic string.
            // Emit mode still writes them (schema fields).
            let mut actual_cmp = actual.clone();
            if let Some(o) = actual_cmp.as_object_mut() {
                o.remove("reason");
                o.remove("note");
            }
            if actual_cmp == expected {
                nice += 1;
            } else {
                coal += 1;
                coal_list.push((short.clone(), name, actual, expected));
            }
        }
    }

    println!(
        "vixen: {nice} nice / {coal} coal / {total} entries across {} files",
        files.len()
    );
    for (file, name, actual, expected) in coal_list.iter().take(60) {
        println!("\nCOAL  {file}  ::  {name}");
        println!("  actual:   {actual}");
        println!("  expected: {expected}");
    }
    if coal_list.len() > 60 {
        println!("\n... and {} more coal entries", coal_list.len() - 60);
    }
}

/// Emit mode: write one actuals file per vector (`<out-dir>/<same-filename>`),
/// each an object mapping entry `name` → its `{ value, cost, error }`. Blind —
/// never reads `expected`. Exit 0 once every actuals file is written.
fn emit(vectors_dir: &Path, out_dir: &Path) {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_vector_files(vectors_dir, &mut files);
    files.sort();
    if files.is_empty() {
        eprintln!("no .json vector files found at {}", vectors_dir.display());
        std::process::exit(2);
    }
    std::fs::create_dir_all(out_dir).expect("create out dir");

    let mut written = 0u64;
    for f in &files {
        let entries = run_vector_file(f);
        if entries.is_empty() {
            continue; // not an eval vector → no actuals file
        }
        let mut actuals = serde_json::Map::new();
        for (name, actual, _expected) in entries {
            actuals.insert(name, actual);
        }
        let filename = f.file_name().expect("vector filename");
        let out_path = out_dir.join(filename);
        let text = serde_json::to_string_pretty(&J::Object(actuals)).expect("serialize actuals");
        std::fs::write(&out_path, text).expect("write actuals file");
        written += 1;
    }
    eprintln!("vixen emit: wrote {written} actuals files to {}", out_dir.display());
}

/// Collect `.json` vector files; directories recurse (the committed corpus
/// nests as vectors/eval/<version>/<provenance>/, while the orchestrator
/// stages flat — both shapes work).
fn collect_vector_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for e in std::fs::read_dir(path).expect("read dir").flatten() {
            collect_vector_files(&e.path(), out);
        }
    } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
        out.push(path.to_path_buf());
    }
}
