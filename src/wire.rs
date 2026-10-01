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
use ergo_ser::block_transactions::{read_block_transactions, write_block_transactions_with_version};
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

/// Scala's and arkadianet's `MAX_TRANSACTIONS_IN_BLOCK`: a section's first u32
/// above it is `10,000,000 + block version`; at or below it, it is the
/// transaction count of a version-1 block.
const BLOCK_VERSION_MARKER_BASE: u32 = 10_000_000;

/// The block version a section declares. arkadianet's writer needs it back:
/// its `BlockTransactions` does not keep it.
fn section_block_version(bytes: &[u8]) -> Result<u8, ()> {
    let mut r = VlqReader::new(bytes);
    r.get_array::<32>().map_err(drop)?;
    let ver_or_count = r.get_u32_exact().map_err(drop)?;
    Ok(if ver_or_count > BLOCK_VERSION_MARKER_BASE {
        (ver_or_count - BLOCK_VERSION_MARKER_BASE) as u8
    } else {
        1
    })
}

/// Parse-then-reserialize one kind under the entry's activated script version
/// (runner-contract-wire §1: version is an input). arkadianet's reader takes
/// that version from its caller; a reader without one is in Scala's default
/// context, activated 1. `Err(())` collapses every impl-side failure (parse or
/// write) into the `errored` outcome — the round-trip could not reproduce the
/// blessed bytes.
fn roundtrip(kind: &str, bytes: &[u8], activated: u8) -> Option<Result<Vec<u8>, ()>> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
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
            Ok(SigmaValue::SigmaProp(sb)) => write_sigma_boolean(&mut w, &sb)
                .map_err(drop)
                .map(|()| w.result()),
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
            let mut tr = VlqReader::new(&lenient).with_activated_script_version(activated);
            read_ergo_tree(&mut tr)
                .map_err(drop)
                .and_then(|mut t| {
                    t.has_size = had_size;
                    write_ergo_tree(&mut w, &t).map_err(drop)
                })
                .map(|()| w.result())
        }
        // A block's transactions section, read as a node reads one: on a reader
        // with no activated version of its own. arkadianet's section reader
        // scopes each transaction to (block version - 1) from block version 4,
        // and leaves an earlier block's in the reader's context, Scala's default
        // (`BlockTransactionsSerializer.parse`). So the entry's version pair does
        // not reach a section (runner-contract-wire §5).
        "BlockTransactions" => {
            let mut section = VlqReader::new(bytes);
            read_block_transactions(&mut section)
                .map_err(drop)
                .and_then(|bt| {
                    let version = section_block_version(bytes)?;
                    write_block_transactions_with_version(&mut w, &bt, version).map_err(drop)
                })
                .map(|()| w.result())
        }
        _ => return None,
    })
}

/// Round-trip one wire entry. `kind` selects the codec; `activated` is the
/// entry's `version.activated`.
pub fn run_entry(kind: &str, bytes_hex: &str, activated: u8) -> WireOutcome {
    let bytes = match sval::hex_decode(bytes_hex) {
        Ok(b) => b,
        Err(e) => return WireOutcome::Panicked { note: format!("bad bytes_hex: {e:?}") },
    };
    match roundtrip(kind, &bytes, activated) {
        None => WireOutcome::NotImplemented,
        Some(Ok(out)) => WireOutcome::RoundTrip { bytes_hex: sval::hex_lower(&out) },
        Some(Err(())) => WireOutcome::Errored,
    }
}

#[cfg(test)]
mod tests {
    use super::run_entry;
    use serde_json::Value as J;

    /// Round-trip fixtures from santa's committed wire corpus, under the v6 context.
    fn assert_rt(kind: &str, hex: &str) {
        assert_rt_at(kind, hex, 3);
    }

    fn assert_rt_at(kind: &str, hex: &str, activated: u8) {
        let j = run_entry(kind, hex, activated).to_json();
        assert_eq!(j["error"], J::Null, "{kind}: {j}");
        assert_eq!(j["bytes_hex"], hex, "{kind}");
    }

    /// A box: value 1000000, `tree`, creation height 1, no tokens, no registers,
    /// a tx id, index 0.
    fn box_with_tree(tree: &str) -> String {
        format!("c0843d{tree}010000{}00", "1d".repeat(32))
    }

    /// A block section: a header id, `marker` = VLQ(10,000,000 + block version),
    /// and one transaction — one input (a box id, no proof, no extension), no
    /// data inputs, no tokens, one output (value 1000000, `tree`, height 1, no
    /// tokens, no registers).
    fn section(marker: &str, tree: &str) -> String {
        let (header_id, input) = ("aa".repeat(32), "bb".repeat(32));
        format!("{header_id}{marker}0101{input}0000000001c0843d{tree}010000")
    }

    const V4_TREE: &str = "0c0208d3"; // size-flagged, SigmaProp(true)
    const V3_TREE: &str = "0b0208d3";
    const BLOCK_V4: &str = "84ade204";
    const BLOCK_V3: &str = "83ade204";

    /// The entry's activated version reaches arkadianet's reader. A reader without
    /// one is in Scala's default context, activated 1, where a tree of any version
    /// parses.
    #[test]
    fn a_box_whose_tree_is_above_the_activated_version_is_refused() {
        let j = run_entry("Box", &box_with_tree(V4_TREE), 3).to_json();
        assert_eq!(j["error"], "errored", "{j}");
    }

    #[test]
    fn the_activated_version_is_the_entrys_own() {
        assert_rt_at("Box", &box_with_tree(V3_TREE), 3);
        let j = run_entry("Box", &box_with_tree(V3_TREE), 2).to_json();
        assert_eq!(j["error"], "errored", "{j}");
    }

    /// A block section takes its transactions' context from its own block version,
    /// as a node does (Scala `BlockTransactionsSerializer.parse`): (version - 1)
    /// from block version 4, and none below that.
    #[test]
    fn a_block_section_of_version_4_refuses_a_tree_above_v3() {
        let j = run_entry("BlockTransactions", &section(BLOCK_V4, V4_TREE), 3).to_json();
        assert_eq!(j["error"], "errored", "{j}");
    }

    #[test]
    fn a_block_section_of_version_4_round_trips_a_v3_tree() {
        assert_rt_at("BlockTransactions", &section(BLOCK_V4, V3_TREE), 3);
    }

    /// The entry's activated version does not reach a section: at 2, a v4 tree in
    /// a block of version 3 is above both, and still parses.
    #[test]
    fn a_block_section_below_version_4_takes_a_tree_of_any_version() {
        assert_rt_at("BlockTransactions", &section(BLOCK_V3, V4_TREE), 2);
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
        let j = run_entry("Nope", "00", 3).to_json();
        assert_eq!(j["error"], "not-implemented");
        assert_eq!(j["bytes_hex"], J::Null);
    }

    #[test]
    fn refused_bytes_are_errored() {
        // Truncated box bytes — the impl's parse verdict, not a panic.
        let j = run_entry("Box", "00", 3).to_json();
        assert_eq!(j["error"], "errored");
    }
}
