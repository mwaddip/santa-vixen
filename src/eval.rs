//! Eval wiring: build the contract's canonical context (runner-contract.md
//! §2), evaluate a vector's tree applied to its input (bound at context
//! extension var 1) under the entry's versions, and capture the raw JIT cost.
//!
//! Eval entry: `ergo_sigma::evaluator::conformance::eval_to_value_with_cost`
//! — the additive hook applied to the arkadianet checkout by
//! `patches/0001-conformance-eval-hook.patch`. DeserializeContext nodes are
//! evaluated INLINE by arkadianet's production evaluator (no eager pre-pass);
//! the runner adds nothing — whatever the impl does is what gets graded.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{AvlTreeData, SigmaValue};
use ergo_sigma::evaluator::{conformance, EvalBox, EvalError, ReductionContext};
use ergo_validation::test_helpers::candidate_to_eval_box;
use indexmap::IndexMap;

use crate::sval;

/// secp256k1 group generator, SEC1-compressed — the pinned
/// `preHeader.minerPk` (runner-contract.md §2).
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98,
];

/// One entry's outcome, per the runner contract §3.
pub enum Outcome {
    Success { value: serde_json::Value, cost: u64 },
    Errored,
    /// Typed coverage gap: the impl reports it has no implementation for
    /// this op/method/type (`EvalError::UnsupportedOpcode` /
    /// `UnsupportedConstant`) — distinct from a failed evaluation.
    NotImplemented,
    /// A failure that isn't a clean eval `errored`: an uncaught panic caught
    /// by main's net, or a SANTA-bridge failure (input decode / result
    /// encode) recorded directly. Always coal, message in `note`.
    Panicked { note: String },
}

impl Outcome {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Outcome::Success { value, cost } => {
                serde_json::json!({"value": value, "cost": cost, "error": null})
            }
            Outcome::Errored => {
                serde_json::json!({"value": null, "cost": null, "error": "errored"})
            }
            Outcome::NotImplemented => {
                serde_json::json!({"value": null, "cost": null, "error": "not-implemented"})
            }
            Outcome::Panicked { note } => {
                serde_json::json!({"value": null, "cost": null, "error": "panicked", "note": note})
            }
        }
    }
}

/// Map an eval failure to its contract outcome: the typed "I don't implement
/// this" conditions are `not-implemented` (a coverage fact); everything else
/// — including the JVM-mirroring NotExecutable/Deprecated/Internal opcode
/// rejections, which the reference interpreter also throws on — is `errored`.
fn eval_failure_outcome(e: EvalError) -> Outcome {
    match e {
        EvalError::UnsupportedOpcode(_) | EvalError::UnsupportedConstant(_) => {
            Outcome::NotImplemented
        }
        _ => Outcome::Errored,
    }
}

/// Map an input-decode failure to its contract outcome: the library REFUSING
/// the bytes (its parse verdict on oracle-blessed material) is `errored`; any
/// other bridge failure (malformed SANTA JSON, unsupported kind) is the
/// runner's own ⇒ `panicked` with the cause in `note`.
fn decode_failure_outcome(e: sval::BridgeError, site: &str) -> Outcome {
    match e {
        sval::BridgeError::Refused(_) => Outcome::Errored,
        other => Outcome::Panicked { note: format!("{site}: {other:?}") },
    }
}

/// Make tree bytes leniently parseable for EVAL. arkadianet mirrors mainnet
/// consensus at parse: a size-flagged tree whose root is a non-SigmaProp
/// `Const` wraps as unparsed (Scala's CheckDeserializedScriptIsSigmaProp
/// equivalent), but SANTA corpus roots are arbitrary-typed — the blesser does
/// the equivalent lenient deserialize. Clearing the size bit and dropping the
/// size VLQ routes parsing through the non-sized path, which returns the
/// Const verbatim. (The SELF box still carries the ORIGINAL bytes.)
fn lenient_tree_bytes(bytes: &[u8]) -> Vec<u8> {
    const HAS_SIZE: u8 = 0x08;
    if bytes.is_empty() || bytes[0] & HAS_SIZE == 0 {
        return bytes.to_vec();
    }
    // The size is a VLQ-u32 starting at index 1; skip it.
    let mut end = 1;
    while end < bytes.len() && bytes[end] & 0x80 != 0 {
        end += 1;
    }
    end += 1; // include the final VLQ byte (high bit clear)
    let mut out = Vec::with_capacity(bytes.len().saturating_sub(end - 1));
    out.push(bytes[0] & !HAS_SIZE);
    out.extend_from_slice(bytes.get(end..).unwrap_or_default());
    out
}

type Extension = IndexMap<u8, (SigmaType, SigmaValue)>;

/// Decode v4 `selfRegisters` ("4".."9" → SValue) into a densely-packed
/// register block. A gap (e.g. R4 + R6 without R5) is a malformed vector ⇒
/// `Err(note)` for a `panicked` outcome.
fn decode_self_registers(
    reg_map: &serde_json::Map<String, serde_json::Value>,
) -> Result<AdditionalRegisters, Outcome> {
    let mut pairs: Vec<(u8, RegisterValue)> = Vec::with_capacity(reg_map.len());
    for (k, v) in reg_map {
        let id: u8 = match k.parse() {
            Ok(n @ 4..=9) => n,
            _ => {
                return Err(Outcome::Panicked {
                    note: format!("v4 selfRegisters: bad key {k:?}"),
                })
            }
        };
        match sval::decode_constant(v) {
            Ok((tpe, value)) => pairs.push((id, RegisterValue { tpe, value })),
            Err(e) => return Err(decode_failure_outcome(e, &format!("v4 selfRegisters[{k}]"))),
        }
    }
    pairs.sort_by_key(|(id, _)| *id);
    for (i, (id, _)) in pairs.iter().enumerate() {
        if *id != 4 + i as u8 {
            return Err(Outcome::Panicked {
                note: format!("v4 selfRegisters: not densely packed from R4 (found R{id} at slot {i})"),
            });
        }
    }
    Ok(AdditionalRegisters {
        registers: pairs.into_iter().map(|(_, rv)| rv).collect(),
    })
}

/// Build the SELF box per the canonical context pin: value 1000000, ergoTree
/// = the entry's own (ORIGINAL) tree bytes, txId = 32 zero bytes, index 0,
/// creationHeight 0, no tokens; registers only via v4 `selfRegisters`.
/// Routed through the production `candidate_to_eval_box` bridge so id /
/// raw_bytes are computed exactly as the node computes them.
fn build_self_box(tree_bytes: &[u8], registers: AdditionalRegisters) -> Result<EvalBox, Outcome> {
    let mut r = VlqReader::new(tree_bytes);
    let tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        // The impl refuses a blessed tree: its own verdict ⇒ errored.
        Err(_) => return Err(Outcome::Errored),
    };
    let mut rw = VlqWriter::new();
    if let Err(e) = ergo_ser::register::write_registers(&mut rw, &registers) {
        return Err(Outcome::Panicked { note: format!("SELF register serialize: {e}") });
    }
    let register_bytes = rw.result();
    // from_trusted_raw_parts: tree bytes verbatim (the entry's own bytes ARE
    // the canonical serialization — arkadianet's byte-round-trip invariant).
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        1_000_000,
        tree,
        tree_bytes.to_vec(),
        0,
        Vec::new(),
        registers,
        register_bytes,
    );
    candidate_to_eval_box(&candidate, &ModifierId::from_bytes([0u8; 32]), 0)
        .map_err(|e| Outcome::Panicked { note: format!("SELF box bridge: {e}") })
}

/// The pinned `LastBlockUtxoRootHash`: 33-byte all-zero digest, all
/// operations allowed (flags 0x07), keyLength 32, no value-length.
fn dummy_avl_tree() -> AvlTreeData {
    AvlTreeData {
        digest: [0u8; 33].into(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    }
}

/// Evaluate one entry. Produces exactly one [`Outcome`] (totality, §3).
pub fn run_entry(
    tree_bytes: &[u8],
    input: Option<&serde_json::Value>,
    inputs: Option<&Vec<serde_json::Value>>,
    self_registers: Option<&serde_json::Map<String, serde_json::Value>>,
    tree_version: u8,
    activated_version: u8,
) -> Outcome {
    // v4: SELF carries custom non-mandatory registers (decoded first so a
    // malformed register map surfaces before any eval work).
    let registers = match self_registers {
        Some(reg_map) => match decode_self_registers(reg_map) {
            Ok(r) => r,
            Err(outcome) => return outcome,
        },
        None => AdditionalRegisters::empty(),
    };

    // v2/v4 input: a single SValue bound at context extension var 1.
    let mut extension: Extension = IndexMap::new();
    if let Some(j) = input {
        match sval::decode_constant(j) {
            Ok(tv) => {
                extension.insert(1u8, tv);
            }
            Err(e) => return decode_failure_outcome(e, "input decode"),
        }
    }

    // v3 (getVarFromInput): per-input extensions — one {varId → constant}
    // map per spending-tx input, read by index. The boxes stay [SELF].
    let mut input_extensions: Vec<Extension> = Vec::new();
    if let Some(arr) = inputs {
        for inp in arr {
            let mut ext: Extension = IndexMap::new();
            if let Some(map) = inp.get("extension").and_then(|e| e.as_object()) {
                for (k, v) in map {
                    let id: u8 = match k.parse() {
                        Ok(id) => id,
                        Err(_) => {
                            return Outcome::Panicked {
                                note: format!("v3 extension: bad var id {k:?}"),
                            }
                        }
                    };
                    match sval::decode_constant(v) {
                        Ok(tv) => {
                            ext.insert(id, tv);
                        }
                        Err(e) => return decode_failure_outcome(e, "input decode (v3)"),
                    }
                }
            }
            input_extensions.push(ext);
        }
    }

    // SELF (original bytes — byte-faithful propositionBytes / id), then the
    // eval tree (lenient bytes — arbitrary-typed roots parse).
    let self_box = match build_self_box(tree_bytes, registers) {
        Ok(b) => b,
        Err(outcome) => return outcome,
    };
    let lenient = lenient_tree_bytes(tree_bytes);
    let mut r = VlqReader::new(&lenient);
    let tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(_) => return Outcome::Errored,
    };

    let tx_inputs = std::slice::from_ref(&self_box);
    let avl_dummy = dummy_avl_tree();
    let ctx = ReductionContext {
        height: 0,
        self_box: Some(&self_box),
        self_creation_height: 0,
        outputs: &[],
        inputs: tx_inputs,
        data_inputs: &[],
        miner_pubkey: GENERATOR,
        pre_header_timestamp: 3,
        pre_header_version: activated_version + 1,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        extension,
        input_extensions: &input_extensions,
        last_headers: &[],
        last_block_utxo_root: Some(avl_dummy),
        activated_script_version: activated_version,
        // The entry's declared version.ergoTree (contract §3: version is an
        // input — the (activated, ergoTree) pair). Distinct from activated:
        // a legacy tree can be spent under a newer activation, and the impl
        // keys several v6 behaviors on the TREE version.
        ergo_tree_version: tree_version,
    };

    let mut cost = CostAccumulator::recording_only();
    match conformance::eval_to_value_with_cost(&tree.body, &ctx, &tree.constants, &mut cost) {
        Ok(v) => {
            let env = sval::BoxEnv {
                self_box: &self_box,
                inputs: tx_inputs,
                outputs: &[],
                data_inputs: &[],
            };
            match sval::encode_value(&v, &env) {
                Ok(value) => Outcome::Success { value, cost: cost.total().value() },
                Err(e) => Outcome::Panicked { note: format!("result encode: {e:?}") },
            }
        }
        Err(e) => eval_failure_outcome(e),
    }
}
