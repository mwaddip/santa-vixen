//! Chain-tier wiring: header-chain-decidable consensus functions per
//! `runner-contract-chain.md` — kind dispatch per entry, two kinds:
//!
//! - **retargeting** — anchor headers → required `nBits` for a target
//!   height, via `ergo_crypto::difficulty::next_n_bits` (the same fn the
//!   node's verifier and miner share).
//! - **voting** — epoch vote stream + in-force parameters + proposed
//!   update → the full next-Parameters table + the activated update, via
//!   `compute_epoch_votes` (the seeded tally) + `compute_next_params`
//!   (the boundary pair function).
//!
//! §5 self-containment: every value the computation reads comes from
//! `entry.settings` / `entry.payload` — `DifficultyParams` and
//! `VotingSettings` are built per entry, never from a network preset.
//! (One impl-shaped caveat: arkadianet hardcodes `use_last_epochs = 8`
//! as a consensus constant — its API takes no such parameter, so the
//! entry's value is not threaded. Every v1 vector carries 8; a future
//! vector carrying anything else would grade arkadianet's 8, faithfully.)

use ergo_chain_spec::DifficultyParams;
use ergo_crypto::difficulty::next_n_bits;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::Header;
use ergo_validation::voting::{compute_epoch_votes, compute_next_params, VotingSettings};
use ergo_validation::{
    ChainHeaderReader, ChainHeaderReaderError, ErgoValidationSettingsUpdate, HeaderView,
};
use serde_json::Value as J;

use crate::block::{decode_header_json, params_from_table};
use crate::sval;

/// One chain entry's outcome (contract §3). The union actuals shape is
/// legal (the other kind's value keys null); we emit per-kind fields.
pub enum ChainOutcome {
    Retargeted { nbits: u32 },
    Voted { table: serde_json::Map<String, J>, activated_update: String },
    Errored { note: String },
    NotImplemented,
    Panicked { note: String },
}

impl ChainOutcome {
    pub fn to_json(&self) -> J {
        match self {
            ChainOutcome::Retargeted { nbits } => serde_json::json!({
                "nbits": nbits, "error": null,
            }),
            ChainOutcome::Voted { table, activated_update } => serde_json::json!({
                "parameters": {"table": table},
                "activated_update": activated_update,
                "error": null,
            }),
            ChainOutcome::Errored { note } => serde_json::json!({
                "nbits": null, "parameters": null, "activated_update": null,
                "error": "errored", "note": note,
            }),
            ChainOutcome::NotImplemented => serde_json::json!({
                "nbits": null, "parameters": null, "activated_update": null,
                "error": "not-implemented",
            }),
            ChainOutcome::Panicked { note } => serde_json::json!({
                "nbits": null, "parameters": null, "activated_update": null,
                "error": "panicked", "note": note,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// retargeting
// ---------------------------------------------------------------------------

fn run_retargeting(settings: &J, payload: &J) -> Result<ChainOutcome, String> {
    let u32_of = |j: &J, what: &str| -> Result<u32, String> {
        j.as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| format!("{what} missing or out of range"))
    };

    let epoch_length = u32_of(&settings["epoch_length"], "settings.epoch_length")?;
    let block_interval_ms = settings["block_interval_ms"]
        .as_u64()
        .ok_or("settings.block_interval_ms missing")?;
    let initial_nbits = u32_of(&settings["initial_nbits"], "settings.initial_nbits")?;
    // Optional EIP-37 pair — present ⇒ the arm is settings-armed and
    // governs iff target_height ≥ activation (the impl's own dispatch).
    let eip37_activation_height = match &settings["eip37_activation_height"] {
        J::Null => None,
        v => Some(u32_of(v, "settings.eip37_activation_height")?),
    };
    let eip37_epoch_length = match &settings["eip37_epoch_length"] {
        J::Null => None,
        v => Some(u32_of(v, "settings.eip37_epoch_length")?),
    };

    let target_height = u32_of(&payload["target_height"], "payload.target_height")?;
    let anchors_json = payload["anchor_headers"]
        .as_array()
        .ok_or("payload.anchor_headers missing")?;
    let mut anchors: Vec<Header> = Vec::with_capacity(anchors_json.len());
    for h in anchors_json {
        let (_, _, header) = decode_header_json(h)?;
        anchors.push(header);
    }

    // initialDifficulty: from initial_nbits via decodeCompactBits
    // (contract §5), big-endian bytes as the impl carries it.
    let initial_difficulty = decode_compact_bits(initial_nbits).to_bytes_be();

    let config = DifficultyParams {
        epoch_length,
        eip37_epoch_length,
        eip37_activation_height,
        // §2 carve-out: v1 vectors avoid the version-2 reset heights, so
        // no transition descriptor is in play (and none is in the entry).
        v2_activation: None,
        initial_difficulty,
        desired_interval_ms: block_interval_ms,
    };

    match next_n_bits(target_height, &anchors, &config) {
        Ok(nbits) => Ok(ChainOutcome::Retargeted { nbits }),
        Err(e) => Ok(ChainOutcome::Errored { note: format!("retargeting: {e:?}") }),
    }
}

// ---------------------------------------------------------------------------
// voting
// ---------------------------------------------------------------------------

/// `ChainHeaderReader` over the entry's `vote_stream` — heights map to
/// raw 3-byte votes; anything outside the stream is a missing row (the
/// computation must never need one for a well-formed vector).
struct VoteStreamReader {
    votes_by_height: std::collections::HashMap<u32, [u8; 3]>,
}

impl ChainHeaderReader for VoteStreamReader {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        self.votes_by_height
            .get(&height)
            .map(|votes| HeaderView { votes: *votes })
            .ok_or(ChainHeaderReaderError::NotFound(height))
    }
}

fn votes3(hex: &str, what: &str) -> Result<[u8; 3], String> {
    let b = sval::hex_decode(hex).map_err(|e| format!("{what}: {e:?}"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| format!("{what}: {} bytes != 3", b.len()))
}

/// The full post-epoch table in the vector's stringified-int-key shape:
/// the named always-present ids (1–8, 123), id 9 when carried, and any
/// extra ids verbatim — the same id set the impl's own params codec
/// emits.
fn table_json(p: &ergo_validation::active_params::ActiveProtocolParameters) -> serde_json::Map<String, J> {
    let mut t = serde_json::Map::new();
    let mut put = |id: u8, v: i64| {
        t.insert(id.to_string(), serde_json::json!(v));
    };
    put(1, p.storage_fee_factor as i64);
    put(2, p.min_value_per_byte as i64);
    put(3, p.max_block_size as i64);
    put(4, p.max_block_cost as i64);
    put(5, p.token_access_cost as i64);
    put(6, p.input_cost as i64);
    put(7, p.data_input_cost as i64);
    put(8, p.output_cost as i64);
    if let Some(sb) = p.subblocks_per_block {
        put(9, sb as i64);
    }
    for (id, v) in &p.extra {
        put(*id, *v as i64);
    }
    put(123, p.block_version as i64);
    t
}

fn run_voting(settings: &J, payload: &J) -> Result<ChainOutcome, String> {
    let u32_of = |j: &J, what: &str| -> Result<u32, String> {
        j.as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| format!("{what} missing or out of range"))
    };

    let voting_settings = VotingSettings {
        voting_length: u32_of(&settings["voting_length"], "settings.voting_length")?,
        soft_fork_epochs: u32_of(&settings["soft_fork_epochs"], "settings.soft_fork_epochs")?,
        activation_epochs: u32_of(&settings["activation_epochs"], "settings.activation_epochs")?,
        version2_activation: match &settings["version2_activation_height"] {
            J::Null => None,
            v => Some(u32_of(v, "settings.version2_activation_height")?),
        },
    };

    let boundary_height = u32_of(&payload["boundary_height"], "payload.boundary_height")?;
    let cur_table = payload["current_parameters"]["table"]
        .as_object()
        .ok_or("payload.current_parameters.table missing")?;
    let prev_active = params_from_table(cur_table)?;

    let stream = payload["vote_stream"]
        .as_array()
        .ok_or("payload.vote_stream missing")?;
    let mut votes_by_height = std::collections::HashMap::with_capacity(stream.len());
    for row in stream {
        let h = u32_of(&row["height"], "vote_stream.height")?;
        let v = votes3(row["votes"].as_str().ok_or("vote_stream.votes missing")?, "vote_stream.votes")?;
        votes_by_height.insert(h, v);
    }
    let reader = VoteStreamReader { votes_by_height };

    // The seeded tally over the window [T − L, T − 1] — the impl's own
    // walker (seed = previous boundary's votes; unseeded ids drop;
    // chain-start clamp seeds empty).
    let epoch_votes = compute_epoch_votes(&reader, boundary_height, voting_settings.voting_length)
        .map_err(|e| format!("epoch tally: {e:?}"))?;

    // forkVote from the boundary header's OWN votes (never tallied).
    let boundary_votes = votes3(
        payload["boundary_votes"].as_str().ok_or("payload.boundary_votes missing")?,
        "payload.boundary_votes",
    )?;
    let fork_vote = boundary_votes.iter().any(|&v| v as i8 == 120);

    let proposed_hex = payload["proposed_update"]
        .as_str()
        .ok_or("payload.proposed_update missing")?;
    let proposed_bytes = sval::hex_decode(proposed_hex).map_err(|e| format!("{e:?}"))?;
    let proposed_update = ErgoValidationSettingsUpdate::deserialize(&proposed_bytes)
        .map_err(|e| format!("proposed_update decode: {e:?}"))?;

    match compute_next_params(
        &prev_active,
        &epoch_votes,
        fork_vote,
        &proposed_update,
        boundary_height,
        &voting_settings,
    ) {
        Ok((next, activated)) => Ok(ChainOutcome::Voted {
            table: table_json(&next),
            activated_update: sval::hex_lower(&activated.serialize()),
        }),
        Err(e) => Ok(ChainOutcome::Errored { note: format!("voting: {e:?}") }),
    }
}

/// Run one chain entry: kind dispatch; decode failures land `errored`;
/// an unknown kind is `not-implemented` (per-kind ledger state).
pub fn run_entry(entry: &J) -> ChainOutcome {
    let kind = entry["kind"].as_str().unwrap_or("");
    let result = match kind {
        "retargeting" => run_retargeting(&entry["settings"], &entry["payload"]),
        "voting" => run_voting(&entry["settings"], &entry["payload"]),
        _ => return ChainOutcome::NotImplemented,
    };
    match result {
        Ok(outcome) => outcome,
        Err(note) => ChainOutcome::Errored { note },
    }
}
