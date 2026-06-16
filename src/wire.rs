//! Wire-tier round-trip: parse a `kind`'s canonical bytes with arkadianet's
//! ergo-ser codec and reserialize for byte-identity comparison downstream
//! (runner-contract-wire.md). A parse/serialize failure is `errored` — the
//! impl rejected (or could not reproduce) bytes the JVM blessed, a real
//! divergence; a `kind` with no codec wired here is `not-implemented`.
//!
//! Byte-round-trip identity is ergo-ser's own core invariant (consensus IDs
//! are hashes of canonical bytes), so this tier exercises the node's
//! serializer exactly as the node uses it.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_constant, read_value, write_constant, write_sigma_boolean, SigmaValue};

use crate::eval::lenient_tree_bytes;
use crate::sval;

/// One wire entry's outcome — the round-trip analog of
/// [`crate::eval::Outcome`]: `bytes_hex` replaces value+cost (the wire tier
/// has no cost dimension).
pub enum WireOutcome {
    RoundTrip { bytes_hex: String },
    Errored,
    NotImplemented,
    Panicked { note: String },
}

impl WireOutcome {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            WireOutcome::RoundTrip { bytes_hex } => {
                serde_json::json!({"bytes_hex": bytes_hex, "error": null})
            }
            WireOutcome::Errored => serde_json::json!({"bytes_hex": null, "error": "errored"}),
            WireOutcome::NotImplemented => {
                serde_json::json!({"bytes_hex": null, "error": "not-implemented"})
            }
            WireOutcome::Panicked { note } => {
                serde_json::json!({"bytes_hex": null, "error": "panicked", "note": note})
            }
        }
    }
}

/// Parse-then-reserialize one kind. `Err(())` collapses every impl-side
/// failure (parse or write) into the `errored` outcome — the round-trip
/// could not reproduce the blessed bytes.
fn roundtrip(kind: &str, bytes: &[u8]) -> Option<Result<Vec<u8>, ()>> {
    let mut r = VlqReader::new(bytes);
    let mut w = VlqWriter::new();
    Some(match kind {
        "Constant" => read_constant(&mut r)
            .map_err(drop)
            .and_then(|(tpe, val)| write_constant(&mut w, &tpe, &val).map_err(drop))
            .map(|()| w.result()),
        "Box" => ergo_ser::ergo_box::read_ergo_box(&mut r)
            .map_err(drop)
            .and_then(|b| ergo_ser::ergo_box::write_ergo_box(&mut w, &b).map_err(drop))
            .map(|()| w.result()),
        "Transaction" => ergo_ser::transaction::read_transaction(&mut r)
            .map_err(drop)
            .and_then(|tx| ergo_ser::transaction::write_transaction(&mut w, &tx).map_err(drop))
            .map(|()| w.result()),
        "Header" => ergo_ser::header::read_header(&mut r)
            .map_err(drop)
            .and_then(|h| ergo_ser::header::write_header(&mut w, &h).map_err(drop))
            .map(|()| w.result()),
        // No public bare read_sigma_boolean — route through the impl's
        // SSigmaProp value reader (same wire form), write the bare form back.
        "SigmaBoolean" => match read_value(&mut r, &SigmaType::SSigmaProp) {
            Ok(SigmaValue::SigmaProp(sb)) => {
                write_sigma_boolean(&mut w, &sb);
                Ok(w.result())
            }
            _ => Err(()),
        },
        // ErgoTree: a STRUCTURAL round-trip (runner-contract-wire §5,
        // "structural, not cached"). Strip the size flag so arkadianet parses
        // the body structurally instead of soft-fork-wrapping a size-flagged
        // non-SigmaProp-root tree as an unparsed `true` placeholder (the
        // prompt's "echo/wrap trap"); the original size flag is restored before
        // re-serialize so a well-formed sized tree round-trips to its sized
        // canonical form. The STypeVar vectors carry ill-formed-UTF-8 type-var
        // names: arkadianet's strict `String::from_utf8` (ergo-ser
        // sigma_type.rs) rejects them at the structural parse → `errored` — the
        // divergence vixen surfaces (the JVM lossy-decodes to U+FFFD and
        // canonicalizes; arkadianet doesn't lossy-decode at all).
        "ErgoTree" => {
            let lenient = lenient_tree_bytes(bytes);
            let had_size = bytes.first().is_some_and(|&h| h & 0x08 != 0);
            let mut tr = VlqReader::new(&lenient);
            read_ergo_tree(&mut tr)
                .map_err(drop)
                .and_then(|mut t| {
                    t.has_size = had_size;
                    write_ergo_tree(&mut w, &t).map_err(drop)
                })
                .map(|()| w.result())
        }
        _ => return None,
    })
}

/// Round-trip one wire entry. `kind` selects the codec.
pub fn run_entry(kind: &str, bytes_hex: &str) -> WireOutcome {
    let bytes = match sval::hex_decode(bytes_hex) {
        Ok(b) => b,
        Err(e) => return WireOutcome::Panicked { note: format!("bad bytes_hex: {e:?}") },
    };
    match roundtrip(kind, &bytes) {
        None => WireOutcome::NotImplemented,
        Some(Ok(out)) => WireOutcome::RoundTrip { bytes_hex: sval::hex_lower(&out) },
        Some(Err(())) => WireOutcome::Errored,
    }
}

#[cfg(test)]
mod tests {
    use super::run_entry;
    use serde_json::Value as J;

    /// Round-trip fixtures from santa's committed wire corpus.
    fn assert_rt(kind: &str, hex: &str) {
        let j = run_entry(kind, hex).to_json();
        assert_eq!(j["error"], J::Null, "{kind}: {j}");
        assert_eq!(j["bytes_hex"], hex, "{kind}");
    }

    #[test]
    fn box_round_trips_to_its_own_bytes() {
        // sbox_minimal from vectors/wire/v5/authored/Box.json
        assert_rt(
            "Box",
            "c0843d09020101000000000000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn sigma_boolean_round_trips_to_its_own_bytes() {
        assert_rt("SigmaBoolean", "d3"); // TrivialProp(true)
    }

    #[test]
    fn constant_round_trips_to_its_own_bytes() {
        assert_rt("Constant", "0101"); // Boolean true
    }

    #[test]
    fn unwired_kind_is_not_implemented() {
        let j = run_entry("Nope", "00").to_json();
        assert_eq!(j["error"], "not-implemented");
        assert_eq!(j["bytes_hex"], J::Null);
    }

    #[test]
    fn refused_bytes_are_errored() {
        // Truncated box bytes — the impl's parse verdict, not a panic.
        let j = run_entry("Box", "00").to_json();
        assert_eq!(j["error"], "errored");
    }
}
