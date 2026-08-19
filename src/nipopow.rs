use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::serialize_nipopow_proof;
use ergo_validation::popow::algos::{
    build_popow_header, pack_interlinks, prove, update_interlinks, PoPowParams,
};
use serde_json::{json, Value as J};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn header_id_hex(h: &Header) -> String {
    let (_bytes, id) = serialize_header(h).expect("serialize header for id");
    bytes_to_hex(id.as_bytes())
}

fn parse_chain(chain_json: &[J]) -> Vec<PoPowHeader> {
    let headers: Vec<Header> = chain_json
        .iter()
        .map(|h| {
            let hex = h["headerHex"].as_str().expect("missing headerHex");
            let bytes = hex_to_bytes(hex);
            let mut reader = ergo_primitives::reader::VlqReader::new(&bytes);
            read_header(&mut reader).expect("header parse failed")
        })
        .collect();

    let mut popow = Vec::with_capacity(headers.len());

    let (_bytes, genesis_id) = serialize_header(&headers[0]).expect("genesis id");
    let genesis_il = vec![genesis_id];
    let packed = pack_interlinks(&genesis_il);
    let genesis_ph = build_popow_header(headers[0].clone(), genesis_il, &packed)
        .expect("genesis popow header");
    popow.push(genesis_ph);

    for i in 1..headers.len() {
        let prev = &popow[i - 1];
        let il = update_interlinks(&prev.header, &prev.interlinks).expect("update_interlinks");
        let packed = pack_interlinks(&il);
        let ph = build_popow_header(headers[i].clone(), il, &packed).expect("popow header");
        popow.push(ph);
    }
    popow
}

pub fn run_interlinks(chain_json: &[J]) -> J {
    let popow = parse_chain(chain_json);
    let il: Vec<J> = popow
        .iter()
        .map(|ph| {
            J::Array(
                ph.interlinks
                    .iter()
                    .map(|id| json!(bytes_to_hex(id.as_bytes())))
                    .collect(),
            )
        })
        .collect();
    json!({ "interlinks": il, "error": null })
}

pub fn run_prove(chain_json: &[J], m: u32, k: u32, header_id: Option<&str>) -> J {
    let popow = parse_chain(chain_json);
    let chain = if let Some(hid) = header_id {
        let hid_lower = hid.to_lowercase();
        let idx = popow
            .iter()
            .position(|ph| header_id_hex(&ph.header) == hid_lower)
            .expect("headerId not found");
        popow[..idx + k as usize + 1].to_vec()
    } else {
        popow
    };

    let params = PoPowParams {
        m,
        k,
        continuous: false,
    };
    let proof = prove(chain, params).expect("prove failed");
    let proof_bytes = serialize_nipopow_proof(&proof).expect("serialize");
    json!({ "proofHex": bytes_to_hex(&proof_bytes), "error": null })
}
