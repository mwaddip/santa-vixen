//! Block-tier wiring: digest-state block validity per
//! `runner-contract-block.md`. Given `parent_digest`, the ≤10-header
//! window, the in-force parameters, and a full block with ADProofs,
//! produce `valid?` + the computed post-state digest (+cost).
//!
//! Mirrors arkadianet's own digest-mode flow
//! (`ergo-sync::block_proc::process_block_digest`), re-composed from its
//! public seams over vector inputs instead of store inputs — patch-free:
//!
//!   PoW (header's own nBits) → proofs-section binding → state-changes
//!   derivation (`build_utxo_changes_raw` + data-input lookups) →
//!   `DigestProofVerifier::apply_block_resolving_boxes` anchored at
//!   `parent_digest` → `DigestUtxoView` → `validate_full_block_parallel_
//!   with_costs` (checkpoint-free).
//!
//! Outcome mapping (contract §3): a clean validation rejection is a
//! VERDICT (`valid:false` + diagnostic `reason`), never `errored`;
//! `errored` is reserved for decode/setup failures on the vector
//! material itself; panics are caught by main's net.

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};
use ergo_state::store::StateStore;
use ergo_state::{DigestProofVerifier, DigestUtxoView};
use ergo_validation::active_params::ActiveProtocolParameters;
use ergo_validation::block::{validate_full_block_parallel_with_costs, BlockValidationContext};
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::{CheckedHeader, PowCheckedHeader};
use ergo_validation::{scala_launch_testnet, ErgoValidationSettingsUpdate};
use ergo_rest_json::decode::decode_scala_header;
use ergo_rest_json::decode::{decode_block_transactions_with_mode, DecodeMode};
use ergo_rest_json::types::{ScalaBlockTransactions, ScalaHeader, ScalaPowSolutions};
use serde_json::Value as J;

use crate::sval;

/// One block entry's outcome (contract §3 actuals shape).
pub enum BlockOutcome {
    /// A verdict: accepted (post_digest computed, cost claimed) or
    /// rejected (diagnostic reason, never matched).
    Verdict {
        valid: bool,
        post_digest: Option<String>,
        cost: Option<u64>,
        reason: Option<String>,
    },
    /// No verdict — the vector material itself failed to decode.
    Errored { reason: String },
    Panicked { note: String },
}

impl BlockOutcome {
    fn reject(reason: String) -> Self {
        BlockOutcome::Verdict { valid: false, post_digest: None, cost: None, reason: Some(reason) }
    }

    pub fn to_json(&self) -> J {
        match self {
            BlockOutcome::Verdict { valid, post_digest, cost, reason } => serde_json::json!({
                "valid": valid,
                "post_digest": post_digest,
                "cost": cost,
                "error": null,
                "reason": reason,
            }),
            BlockOutcome::Errored { reason } => serde_json::json!({
                "valid": null, "post_digest": null, "cost": null,
                "error": "errored", "reason": reason,
            }),
            BlockOutcome::Panicked { note } => serde_json::json!({
                "valid": null, "post_digest": null, "cost": null,
                "error": "panicked", "note": note,
            }),
        }
    }
}

/// Decode a vector header JSON object into canonical header bytes + the
/// parsed `Header`, via the impl's own node-API decoder. The vector
/// carries only the wire-bearing fields; `ScalaHeader`'s derived/cosmetic
/// fields (`extensionId`, `difficulty`, `size`, section ids) are
/// backfilled with defaults — `decode_scala_header` never reads them.
pub(crate) fn decode_header_json(
    h: &J,
) -> Result<(Vec<u8>, [u8; 32], ergo_ser::header::Header), String> {
    let s = |k: &str| -> Result<String, String> {
        h[k].as_str().map(str::to_string).ok_or_else(|| format!("header.{k} missing"))
    };
    let pow: ScalaPowSolutions = serde_json::from_value(h["powSolutions"].clone())
        .map_err(|e| format!("header.powSolutions: {e}"))?;
    let scala = ScalaHeader {
        extension_id: String::new(),
        difficulty: "0".to_string(),
        votes: s("votes")?,
        timestamp: h["timestamp"].as_u64().ok_or("header.timestamp missing")?,
        size: 0,
        unparsed_bytes: h["unparsedBytes"].as_str().unwrap_or("").to_string(),
        state_root: s("stateRoot")?,
        height: h["height"].as_u64().ok_or("header.height missing")? as u32,
        n_bits: h["nBits"].as_u64().ok_or("header.nBits missing")?,
        version: h["version"].as_u64().ok_or("header.version missing")? as u8,
        id: s("id")?,
        ad_proofs_root: s("adProofsRoot")?,
        transactions_root: s("transactionsRoot")?,
        extension_hash: s("extensionHash")?,
        pow_solutions: pow,
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: s("parentId")?,
    };
    let (bytes, _) = decode_scala_header(&scala).map_err(|e| format!("header decode: {e:?}"))?;
    let header_id = *blake2b256(&bytes).as_bytes();
    let mut r = VlqReader::new(&bytes);
    let header = read_header(&mut r).map_err(|e| format!("header re-parse: {e:?}"))?;
    Ok((bytes, header_id, header))
}

/// A vector context header (chain-blessed) as a `CheckedHeader`, via the
/// persisted-parts seam — the same trust boundary the node's digest arm
/// uses for already-accepted headers (`pow_validity = 1`).
fn context_checked_header(h: &J) -> Result<CheckedHeader, String> {
    let (bytes, id, header) = decode_header_json(h)?;
    CheckedHeader::from_persisted_parts(
        &bytes,
        id,
        1,
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    )
    .map_err(|e| format!("context header: {e:?}"))
}

/// Map the vector's `parameters.table` (id-string → int) onto the impl's
/// per-epoch parameter set. Named ids fill their fields (defaults from
/// the testnet launch set for ids the table omits); unrecognized ids ride
/// in `extra` verbatim.
pub(crate) fn params_from_table(
    table: &serde_json::Map<String, J>,
) -> Result<ActiveProtocolParameters, String> {
    let mut p: ActiveProtocolParameters = scala_launch_testnet();
    p.epoch_start_height = 0;
    p.subblocks_per_block = None;
    p.extra = Vec::new();
    p.proposed_update = ErgoValidationSettingsUpdate::default();
    p.activated_update = ErgoValidationSettingsUpdate::default();
    for (k, v) in table {
        let id: u8 = k.parse().map_err(|_| format!("parameters.table: bad id {k:?}"))?;
        let val = v.as_i64().ok_or_else(|| format!("parameters.table[{k}] not an int"))?;
        let val32 = i32::try_from(val).map_err(|_| format!("parameters.table[{k}] out of i32"))?;
        match id {
            1 => p.storage_fee_factor = val32,
            2 => p.min_value_per_byte = val32,
            3 => p.max_block_size = val32,
            4 => p.max_block_cost = val32,
            5 => p.token_access_cost = val32,
            6 => p.input_cost = val32,
            7 => p.data_input_cost = val32,
            8 => p.output_cost = val32,
            9 => p.subblocks_per_block = Some(val32),
            123 => {
                if !(0..=255).contains(&val) {
                    return Err(format!("parameters.table[123] {val} not a u8"));
                }
                p.block_version = val as u8;
            }
            other => p.extra.push((other, val32)),
        }
    }
    Ok(p)
}

/// Validate one block entry. Mirrors `process_block_digest` step for
/// step, seeded fresh at `(parent_digest, height)` (contract §5).
fn validate_entry(entry: &J) -> Result<BlockOutcome, String> {
    // --- decode the determination set (failures here are `errored`) ---
    let parent_digest_hex = entry["parent_digest"]
        .as_str()
        .ok_or("parent_digest missing")?;
    let parent_digest_v = sval::hex_decode(parent_digest_hex).map_err(|e| format!("{e:?}"))?;
    let parent_digest: [u8; 33] = parent_digest_v
        .as_slice()
        .try_into()
        .map_err(|_| format!("parent_digest length {} != 33", parent_digest_v.len()))?;

    let (header_bytes, header_id, header) = decode_header_json(&entry["block"]["header"])?;

    // Block transactions: node-API JSON → canonical wire bytes → parsed,
    // through the impl's own decoder (Preserve: on-chain material). The
    // vector omits the cosmetic per-tx `size` the DTO requires; backfill 0
    // (the decoder derives wire bytes from inputs/dataInputs/outputs only).
    let mut bt_json = entry["block"]["blockTransactions"].clone();
    if let Some(txs) = bt_json.get_mut("transactions").and_then(|t| t.as_array_mut()) {
        for tx in txs {
            if let Some(o) = tx.as_object_mut() {
                o.entry("size").or_insert(serde_json::json!(0));
            }
        }
    }
    let bt: ScalaBlockTransactions = serde_json::from_value(bt_json)
        .map_err(|e| format!("blockTransactions JSON: {e}"))?;
    let bt_bytes = decode_block_transactions_with_mode(&bt, DecodeMode::Preserve)
        .map_err(|e| format!("blockTransactions decode: {e:?}"))?;
    let mut r = VlqReader::new(&bt_bytes);
    let block_txs =
        read_block_transactions(&mut r).map_err(|e| format!("blockTransactions re-parse: {e:?}"))?;

    // Extension: header_id + raw key/value fields.
    let ext_header_id = entry["block"]["extension"]["headerId"]
        .as_str()
        .ok_or("extension.headerId missing")?;
    let ext_header_id_b = sval::hex_decode(ext_header_id).map_err(|e| format!("{e:?}"))?;
    let ext_fields = entry["block"]["extension"]["fields"]
        .as_array()
        .ok_or("extension.fields missing")?;
    let mut fields = Vec::with_capacity(ext_fields.len());
    for f in ext_fields {
        let k = f[0].as_str().ok_or("extension field key")?;
        let v = f[1].as_str().ok_or("extension field value")?;
        let kb = sval::hex_decode(k).map_err(|e| format!("{e:?}"))?;
        let key: [u8; 2] = kb.as_slice().try_into().map_err(|_| "extension key != 2 bytes")?;
        fields.push(ExtensionField { key, value: sval::hex_decode(v).map_err(|e| format!("{e:?}"))? });
    }
    let extension = Extension {
        header_id: ergo_primitives::digest::ModifierId::from_bytes(
            ext_header_id_b
                .as_slice()
                .try_into()
                .map_err(|_| "extension.headerId != 32 bytes")?,
        ),
        fields,
    };

    let proof_bytes = sval::hex_decode(
        entry["block"]["adProofs"]["proofBytes"]
            .as_str()
            .ok_or("adProofs.proofBytes missing")?,
    )
    .map_err(|e| format!("{e:?}"))?;

    let table = entry["parameters"]["table"]
        .as_object()
        .ok_or("parameters.table missing")?;
    let active = params_from_table(table)?;
    let params = ProtocolParams::from_active(&active);

    // Context headers (newest-first; entry 0 = parent at H−1).
    let headers_json = entry["headers"].as_array().ok_or("headers missing")?;
    if headers_json.is_empty() {
        return Err("headers window empty".to_string());
    }
    let mut last_headers = Vec::with_capacity(headers_json.len());
    for h in headers_json {
        last_headers.push(context_checked_header(h)?);
    }
    let parent_checked = context_checked_header(&headers_json[0])?;
    let parent_id = *parent_checked.header_id();

    // --- validation (failures here are verdicts: valid:false) ---

    // 1. PoW against the header's own nBits (contract §5) — Autolykos
    //    seals the whole header, so any header-field tamper lands here.
    let pow_checked = match PowCheckedHeader::verify_pow(header.clone(), header_id) {
        Ok(p) => p,
        Err(e) => return Ok(BlockOutcome::reject(format!("hdrPoW: {e:?}"))),
    };
    drop(pow_checked); // proof of PoW; CheckedHeader is built below via the persisted seam
    if *header.parent_id.as_bytes() != parent_id {
        return Ok(BlockOutcome::reject(format!(
            "header.parentId {} != headers[0].id {}",
            hex32(header.parent_id.as_bytes()),
            hex32(&parent_id),
        )));
    }

    // 2. Proofs-section canonicality (contract §5): the committed section
    //    digest IS blake2b256(proofBytes) and must equal the header root.
    let proof_digest = *blake2b256(&proof_bytes).as_bytes();
    if proof_digest != *header.ad_proofs_root.as_bytes() {
        return Ok(BlockOutcome::reject(format!(
            "adProofsRoot: blake2b256(proofBytes) {} != header.adProofsRoot {}",
            hex32(&proof_digest),
            hex32(header.ad_proofs_root.as_bytes()),
        )));
    }

    // 3. State changes — the impl's own builder (create-then-spend
    //    collapse), plus data-input lookups in tx order (the `toLookup`
    //    prefix of the proof stream).
    let tx_refs: Vec<&ergo_ser::transaction::Transaction> =
        block_txs.transactions.iter().collect();
    let (to_remove, to_insert) = match StateStore::build_utxo_changes_raw(&tx_refs) {
        Ok(maps) => maps,
        Err(e) => return Ok(BlockOutcome::reject(format!("state changes: {e:?}"))),
    };
    let to_lookup: Vec<[u8; 32]> = block_txs
        .transactions
        .iter()
        .flat_map(|tx| tx.data_inputs.iter().map(|di| *di.box_id.as_bytes()))
        .collect();

    // 4. Replay the proof from the ANCHORED parent digest; the verifier
    //    cross-checks the computed root against header.stateRoot and
    //    resolves the spent/data-input boxes from the proof leaves.
    let ad_proofs_id = compute_section_id(TYPE_AD_PROOFS, &header_id, header.ad_proofs_root.as_bytes());
    let (new_root, resolved) = match DigestProofVerifier::apply_block_resolving_boxes(
        ad_proofs_id,
        &proof_bytes,
        &header,
        &parent_digest,
        &to_lookup,
        &to_remove,
        &to_insert,
    ) {
        Ok(ok) => ok,
        Err(e) => return Ok(BlockOutcome::reject(format!("digest apply: {e:?}"))),
    };

    // 5. Full block validation over the proof-backed view (per-tx
    //    structural/monetary/script + section linkage + cost), exactly
    //    the digest-mode context the node builds — checkpoint-free,
    //    parent_extension None (rules 401/402 don't fire), no soft-fork
    //    window, rule 215 disabled (the v6-activated chain setting).
    let digest_view = match DigestUtxoView::new(&resolved, &block_txs.transactions) {
        Ok(v) => v,
        Err(e) => return Ok(BlockOutcome::reject(format!("digest view: {e:?}"))),
    };
    let checked_header = CheckedHeader::from_persisted_parts(
        &header_bytes,
        header_id,
        1,
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    )
    .map_err(|e| format!("checked header: {e:?}"))?;

    let ctx = BlockValidationContext {
        parent: &parent_checked,
        utxo: &digest_view,
        params: &params,
        voting_length: 128, // testnet (the corpus chain); chain constant, not in the table
        votes_unknown_rule_disabled: true,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &last_headers,
        script_validation_checkpoint: None,
    };

    match validate_full_block_parallel_with_costs(checked_header, &block_txs, &extension, &ctx) {
        Ok((_checked_block, costs)) => {
            let total_cost: u64 = costs.iter().map(|(_, c)| *c).sum();
            Ok(BlockOutcome::Verdict {
                valid: true,
                post_digest: Some(sval::hex_lower(&new_root)),
                cost: Some(total_cost),
                reason: None,
            })
        }
        Err(e) => Ok(BlockOutcome::reject(format!("block validation: {e:?}"))),
    }
}

fn hex32(b: &[u8]) -> String {
    sval::hex_lower(b)
}

/// Run one block entry: decode failures land `errored`, validation
/// failures are clean reject verdicts, success carries the computed
/// post-digest + summed block cost.
pub fn run_entry(entry: &J) -> BlockOutcome {
    match validate_entry(entry) {
        Ok(outcome) => outcome,
        Err(reason) => BlockOutcome::Errored { reason },
    }
}
