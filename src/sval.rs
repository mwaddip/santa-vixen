//! SValue ⇄ canonical SANTA JSON bridge (runner-contract.md §4).
//!
//! Two directions:
//!   - [`encode_value`]: an arkadianet eval-result [`Value`] → canonical SValue
//!     JSON. Box-valued results resolve against the entry's [`BoxEnv`]
//!     (SelfBox / BoxRef are context references, not self-contained values).
//!   - [`decode_constant`]: a canonical SValue JSON (an entry's `input`) → an
//!     arkadianet `(SigmaType, SigmaValue)` pair, to bind in the context
//!     extension / SELF registers.
//!
//! Decode philosophy: byte-carrying kinds (SigmaProp / Box / AvlTree / Header)
//! route through `ergo_ser::sigma_value::read_value` — the impl's own wire
//! reader, the same path a production context extension takes — so the
//! *library* speaks on whether it ingests the bytes ([`BridgeError::Refused`]
//! on its error ⇒ runner `errored`). Primitives are constructed directly
//! (no validation to bypass). GroupElement mirrors the wire reader's
//! `from_bytes` (lenient, no curve check) — faithfully arkadianet.

use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_value, write_sigma_boolean, write_value, CollValue, SigmaValue};
use ergo_sigma::evaluator::{EvalBox, Value};
use serde_json::{json, Value as J};

/// A bridge failure. Payload strings are diagnostic context (surfaced only in
/// `panicked` notes / Debug); the contract defers any error-reason taxonomy.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BridgeError {
    /// The bridge cannot encode this arkadianet Value to canonical JSON (a
    /// SANTA-side gap ⇒ `panicked` note, never an excuse outcome).
    Encode(String),
    /// Malformed SANTA JSON on the decode side (the runner's own failure).
    Decode(String),
    /// The library REFUSED structurally-valid input bytes — its own parse
    /// verdict on oracle-blessed material ⇒ runner `errored`.
    Refused(String),
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, BridgeError> {
    if s.len() % 2 != 0 {
        return Err(BridgeError::Decode(format!("odd-length hex: {s}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| BridgeError::Decode(format!("bad hex {s}: {e}")))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// SType bridge (the `{tag}` forms used in Coll.elem and nested positions)
// ---------------------------------------------------------------------------

pub fn encode_stype(t: &SigmaType) -> J {
    match t {
        SigmaType::SAny => json!({"tag": "SAny"}),
        SigmaType::SUnit => json!({"tag": "SUnit"}),
        SigmaType::SBoolean => json!({"tag": "SBoolean"}),
        SigmaType::SByte => json!({"tag": "SByte"}),
        SigmaType::SShort => json!({"tag": "SShort"}),
        SigmaType::SInt => json!({"tag": "SInt"}),
        SigmaType::SLong => json!({"tag": "SLong"}),
        SigmaType::SBigInt => json!({"tag": "SBigInt"}),
        SigmaType::SUnsignedBigInt => json!({"tag": "SUnsignedBigInt"}),
        SigmaType::SGroupElement => json!({"tag": "SGroupElement"}),
        SigmaType::SSigmaProp => json!({"tag": "SSigmaProp"}),
        SigmaType::SBox => json!({"tag": "SBox"}),
        SigmaType::SHeader => json!({"tag": "SHeader"}),
        SigmaType::SPreHeader => json!({"tag": "SPreHeader"}),
        SigmaType::SAvlTree => json!({"tag": "SAvlTree"}),
        SigmaType::SColl(elem) => json!({"tag": "SColl", "elem": encode_stype(elem)}),
        SigmaType::SOption(elem) => json!({"tag": "SOption", "elem": encode_stype(elem)}),
        SigmaType::STuple(items) => {
            let items: Vec<J> = items.iter().map(encode_stype).collect();
            json!({"tag": "STuple", "items": items})
        }
        other => json!({"tag": format!("{other:?}")}),
    }
}

pub fn decode_stype(j: &J) -> Result<SigmaType, BridgeError> {
    let tag = j["tag"]
        .as_str()
        .ok_or_else(|| BridgeError::Decode(format!("SType missing tag: {j}")))?;
    Ok(match tag {
        "SAny" => SigmaType::SAny,
        "SUnit" => SigmaType::SUnit,
        "SBoolean" => SigmaType::SBoolean,
        "SByte" => SigmaType::SByte,
        "SShort" => SigmaType::SShort,
        "SInt" => SigmaType::SInt,
        "SLong" => SigmaType::SLong,
        "SBigInt" => SigmaType::SBigInt,
        "SUnsignedBigInt" => SigmaType::SUnsignedBigInt,
        "SGroupElement" => SigmaType::SGroupElement,
        "SSigmaProp" => SigmaType::SSigmaProp,
        "SBox" => SigmaType::SBox,
        "SHeader" => SigmaType::SHeader,
        "SPreHeader" => SigmaType::SPreHeader,
        "SAvlTree" => SigmaType::SAvlTree,
        "SColl" => SigmaType::SColl(Box::new(decode_stype(&j["elem"])?)),
        "SOption" => SigmaType::SOption(Box::new(decode_stype(&j["elem"])?)),
        "STuple" => {
            let items_json = j["items"]
                .as_array()
                .ok_or_else(|| BridgeError::Decode(format!("STuple items not an array: {j}")))?;
            let items: Vec<SigmaType> = items_json
                .iter()
                .map(decode_stype)
                .collect::<Result<_, _>>()?;
            SigmaType::STuple(items)
        }
        other => return Err(BridgeError::Decode(format!("unsupported SType tag: {other}"))),
    })
}

// ---------------------------------------------------------------------------
// Value → canonical JSON
// ---------------------------------------------------------------------------

/// The context boxes a Box-valued result resolves against (the evaluator's
/// `SelfBox` / `BoxRef {source, index}` are references into these).
pub struct BoxEnv<'a> {
    pub self_box: &'a EvalBox,
    pub inputs: &'a [EvalBox],
    pub outputs: &'a [EvalBox],
    pub data_inputs: &'a [EvalBox],
}

fn box_bytes_hex(b: &EvalBox, what: &str) -> Result<String, BridgeError> {
    if b.raw_bytes.is_empty() {
        return Err(BridgeError::Encode(format!("{what}: EvalBox.raw_bytes empty")));
    }
    Ok(hex_lower(&b.raw_bytes))
}

fn encode_eval_box(b: &EvalBox, what: &str) -> Result<J, BridgeError> {
    Ok(json!({"kind": "Box", "bytes_hex": box_bytes_hex(b, what)?}))
}

pub fn encode_value(v: &Value, env: &BoxEnv<'_>) -> Result<J, BridgeError> {
    use ergo_sigma::evaluator::BoxSource;
    Ok(match v {
        Value::Bool(b) => json!({"kind": "Boolean", "value": b}),
        Value::Byte(x) => json!({"kind": "Byte", "value": x}),
        Value::Short(x) => json!({"kind": "Short", "value": x}),
        Value::Int(x) => json!({"kind": "Int", "value": x}),
        Value::Long(x) => json!({"kind": "Long", "value": x.to_string()}),
        Value::BigInt(x) => json!({"kind": "BigInt", "value": x.to_string()}),
        Value::UnsignedBigInt(x) => json!({"kind": "UnsignedBigInt", "value": x.to_string()}),
        Value::GroupElement(ge) => json!({"kind": "GroupElement", "bytes_hex": hex_lower(&ge[..])}),
        Value::SigmaProp(sb) => {
            let mut w = VlqWriter::new();
            write_sigma_boolean(&mut w, sb);
            json!({"kind": "SigmaProp", "raw_hex": hex_lower(&w.result())})
        }
        Value::AvlTree(data) => {
            let mut w = VlqWriter::new();
            write_value(&mut w, &SigmaType::SAvlTree, &SigmaValue::AvlTree(data.clone()))
                .map_err(|e| BridgeError::Encode(format!("AvlTree serialize: {e}")))?;
            json!({"kind": "AvlTree", "bytes_hex": hex_lower(&w.result())})
        }
        Value::SelfBox => encode_eval_box(env.self_box, "SelfBox")?,
        Value::BoxRef { source, index } => {
            let (coll, what): (&[EvalBox], _) = match source {
                BoxSource::Inputs => (env.inputs, "BoxRef(Inputs)"),
                BoxSource::Outputs => (env.outputs, "BoxRef(Outputs)"),
                BoxSource::DataInputs => (env.data_inputs, "BoxRef(DataInputs)"),
            };
            let b = coll.get(*index).ok_or_else(|| {
                BridgeError::Encode(format!("{what}[{index}] out of range"))
            })?;
            encode_eval_box(b, what)?
        }
        Value::InlineBox(b) => encode_eval_box(b, "InlineBox")?,
        Value::Tuple(items) => {
            let arr: Result<Vec<J>, _> = items.iter().map(|i| encode_value(i, env)).collect();
            json!({"kind": "Tuple", "items": arr?})
        }
        Value::Opt(opt) => match opt {
            Some(inner) => json!({"kind": "Option", "value": encode_value(inner, env)?}),
            None => json!({"kind": "Option", "value": J::Null}),
        },
        Value::CollBool(items) => {
            let arr: Vec<J> = items
                .iter()
                .map(|b| json!({"kind": "Boolean", "value": b}))
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SBoolean"}, "items": arr})
        }
        Value::CollBytes(items) => {
            let arr: Vec<J> = items
                .iter()
                .map(|b| json!({"kind": "Byte", "value": *b as i8}))
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SByte"}, "items": arr})
        }
        Value::CollShort(items) => {
            let arr: Vec<J> = items
                .iter()
                .map(|x| json!({"kind": "Short", "value": x}))
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SShort"}, "items": arr})
        }
        Value::CollInt(items) => {
            let arr: Vec<J> = items
                .iter()
                .map(|x| json!({"kind": "Int", "value": x}))
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SInt"}, "items": arr})
        }
        Value::CollLong(items) => {
            let arr: Vec<J> = items
                .iter()
                .map(|x| json!({"kind": "Long", "value": x.to_string()}))
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SLong"}, "items": arr})
        }
        Value::CollSigmaProp(items) => {
            let arr: Result<Vec<J>, BridgeError> = items
                .iter()
                .map(|sb| {
                    let mut w = VlqWriter::new();
                    write_sigma_boolean(&mut w, sb);
                    Ok(json!({"kind": "SigmaProp", "raw_hex": hex_lower(&w.result())}))
                })
                .collect();
            json!({"kind": "Coll", "elem": {"tag": "SSigmaProp"}, "items": arr?})
        }
        Value::CollBox(items) => {
            let arr: Result<Vec<J>, _> = items.iter().map(|i| encode_value(i, env)).collect();
            json!({"kind": "Coll", "elem": {"tag": "SBox"}, "items": arr?})
        }
        Value::Tokens(items) => {
            // Coll[(Coll[Byte], Long)] — token id bytes + amount.
            let arr: Vec<J> = items
                .iter()
                .map(|(id, amount)| {
                    let id_items: Vec<J> = id
                        .iter()
                        .map(|b| json!({"kind": "Byte", "value": *b as i8}))
                        .collect();
                    json!({"kind": "Tuple", "items": [
                        {"kind": "Coll", "elem": {"tag": "SByte"}, "items": id_items},
                        {"kind": "Long", "value": (*amount as i64).to_string()},
                    ]})
                })
                .collect();
            json!({"kind": "Coll",
                   "elem": {"tag": "STuple", "items": [
                       {"tag": "SColl", "elem": {"tag": "SByte"}}, {"tag": "SLong"}]},
                   "items": arr})
        }
        Value::CollGeneric(items, elem_type) => {
            let arr: Result<Vec<J>, _> = items.iter().map(|i| encode_value(i, env)).collect();
            json!({"kind": "Coll", "elem": encode_stype(elem_type), "items": arr?})
        }
        Value::BoxCollection(source) => {
            // A whole context box collection as a value (CONTEXT.dataInputs /
            // INPUTS / OUTPUTS) — resolve and encode as Coll[SBox].
            let (coll, what): (&[EvalBox], _) = match source {
                BoxSource::Inputs => (env.inputs, "BoxCollection(Inputs)"),
                BoxSource::Outputs => (env.outputs, "BoxCollection(Outputs)"),
                BoxSource::DataInputs => (env.data_inputs, "BoxCollection(DataInputs)"),
            };
            let arr: Result<Vec<J>, _> = coll.iter().map(|b| encode_eval_box(b, what)).collect();
            json!({"kind": "Coll", "elem": {"tag": "SBox"}, "items": arr?})
        }
        Value::CollHeader(items) if items.is_empty() => {
            // The pinned context has EMPTY headers, so this needs no
            // EvalHeader→wire bridge. A nonempty Coll[Header] still lands in
            // the Encode-gap arm below (none is reachable today: headers are
            // pinned empty and the impl refuses SHeader constants).
            json!({"kind": "Coll", "elem": {"tag": "SHeader"}, "items": []})
        }
        // No canonical SValue encoding exists for these (the contract table
        // has no row): Unit, Str, CollHeader/Header (no EvalHeader→wire
        // bridge yet — unreachable today: headers are pinned EMPTY and the
        // impl refuses SHeader constants), Func/Global/PreHeader/
        // BoxCollection markers. Surfaced as a `panicked` note (§3).
        other => {
            return Err(BridgeError::Encode(format!(
                "no canonical SValue encoding for {other:?}"
            )))
        }
    })
}

// ---------------------------------------------------------------------------
// canonical JSON → (SigmaType, SigmaValue)   (entry inputs / selfRegisters)
// ---------------------------------------------------------------------------

/// Decode a byte-carrying kind through the impl's own wire reader
/// (`read_value`) — its parse verdict on the blessed bytes is the
/// library speaking ⇒ `Refused` on error.
fn read_value_bytes(tpe: SigmaType, bytes: &[u8]) -> Result<(SigmaType, SigmaValue), BridgeError> {
    let mut r = VlqReader::new(bytes);
    let v = read_value(&mut r, &tpe)
        .map_err(|e| BridgeError::Refused(format!("{tpe:?} parse: {e}")))?;
    Ok((tpe, v))
}

pub fn decode_constant(j: &J) -> Result<(SigmaType, SigmaValue), BridgeError> {
    let kind = j["kind"]
        .as_str()
        .ok_or_else(|| BridgeError::Decode(format!("SValue missing kind: {j}")))?;
    let num_i64 = |label: &str| -> Result<i64, BridgeError> {
        j["value"]
            .as_i64()
            .ok_or_else(|| BridgeError::Decode(format!("{label} value not an int: {j}")))
    };
    let str_val = |label: &str| -> Result<String, BridgeError> {
        j["value"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BridgeError::Decode(format!("{label} value not a string: {j}")))
    };
    let hex_field = |field: &str| -> Result<Vec<u8>, BridgeError> {
        let s = j[field]
            .as_str()
            .ok_or_else(|| BridgeError::Decode(format!("missing {field}: {j}")))?;
        hex_decode(s)
    };

    Ok(match kind {
        "Boolean" => (
            SigmaType::SBoolean,
            SigmaValue::Boolean(j["value"].as_bool().ok_or_else(|| {
                BridgeError::Decode(format!("Boolean value not a bool: {j}"))
            })?),
        ),
        "Byte" => (SigmaType::SByte, SigmaValue::Byte(num_i64("Byte")? as i8)),
        "Short" => (SigmaType::SShort, SigmaValue::Short(num_i64("Short")? as i16)),
        "Int" => (SigmaType::SInt, SigmaValue::Int(num_i64("Int")? as i32)),
        "Long" => {
            let n: i64 = str_val("Long")?
                .parse()
                .map_err(|e| BridgeError::Decode(format!("Long parse: {e:?}")))?;
            (SigmaType::SLong, SigmaValue::Long(n))
        }
        "BigInt" => {
            let n: num_bigint::BigInt = str_val("BigInt")?
                .parse()
                .map_err(|e| BridgeError::Decode(format!("BigInt parse: {e:?}")))?;
            (SigmaType::SBigInt, SigmaValue::BigInt(n))
        }
        "UnsignedBigInt" => {
            // Same carrier as BigInt (the impl distinguishes by SigmaType —
            // mirrors read_value's SUnsignedBigInt arm).
            let n: num_bigint::BigInt = str_val("UnsignedBigInt")?
                .parse()
                .map_err(|e| BridgeError::Decode(format!("UnsignedBigInt parse: {e:?}")))?;
            (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(n))
        }
        "GroupElement" => {
            // Mirror the wire reader exactly: a fixed 33-byte read, no curve
            // validation (faithfully arkadianet — see read_value's
            // GroupElement::from_bytes).
            let bytes = hex_field("bytes_hex")?;
            let arr: [u8; 33] = bytes.as_slice().try_into().map_err(|_| {
                BridgeError::Decode(format!("GroupElement length {} != 33", bytes.len()))
            })?;
            (
                SigmaType::SGroupElement,
                SigmaValue::GroupElement(GroupElement::from_bytes(arr)),
            )
        }
        "SigmaProp" => read_value_bytes(SigmaType::SSigmaProp, &hex_field("raw_hex")?)?,
        "Box" => read_value_bytes(SigmaType::SBox, &hex_field("bytes_hex")?)?,
        "AvlTree" => read_value_bytes(SigmaType::SAvlTree, &hex_field("bytes_hex")?)?,
        // The impl has no SHeader value carrier; read_value(SHeader) refuses
        // — the library's own verdict on blessed input material ⇒ errored.
        "Header" => read_value_bytes(SigmaType::SHeader, &hex_field("bytes_hex")?)?,
        "Coll" => {
            let elem = decode_stype(&j["elem"])?;
            let items_json = j["items"]
                .as_array()
                .ok_or_else(|| BridgeError::Decode(format!("Coll items not an array: {j}")))?;
            let items: Vec<(SigmaType, SigmaValue)> = items_json
                .iter()
                .map(decode_constant)
                .collect::<Result<_, _>>()?;
            // Mirror read_coll's element-type specialization.
            let coll = match elem {
                SigmaType::SByte => CollValue::Bytes(
                    items
                        .into_iter()
                        .map(|(_, v)| match v {
                            SigmaValue::Byte(b) => Ok(b as u8),
                            other => Err(BridgeError::Decode(format!(
                                "Coll[Byte] item not a Byte: {other:?}"
                            ))),
                        })
                        .collect::<Result<_, _>>()?,
                ),
                SigmaType::SBoolean => CollValue::BoolBits(
                    items
                        .into_iter()
                        .map(|(_, v)| match v {
                            SigmaValue::Boolean(b) => Ok(b),
                            other => Err(BridgeError::Decode(format!(
                                "Coll[Boolean] item not a Boolean: {other:?}"
                            ))),
                        })
                        .collect::<Result<_, _>>()?,
                ),
                _ => CollValue::Values(items.into_iter().map(|(_, v)| v).collect()),
            };
            (SigmaType::SColl(Box::new(elem)), SigmaValue::Coll(coll))
        }
        "Tuple" => {
            let items_json = j["items"]
                .as_array()
                .ok_or_else(|| BridgeError::Decode(format!("Tuple items not an array: {j}")))?;
            let items: Vec<(SigmaType, SigmaValue)> = items_json
                .iter()
                .map(decode_constant)
                .collect::<Result<_, _>>()?;
            let (tpes, vals): (Vec<SigmaType>, Vec<SigmaValue>) = items.into_iter().unzip();
            (SigmaType::STuple(tpes), SigmaValue::Tuple(vals))
        }
        "Option" => {
            if j["value"].is_null() {
                return Err(BridgeError::Decode(
                    "cannot infer element type of Option.None input".to_string(),
                ));
            }
            let (tpe, v) = decode_constant(&j["value"])?;
            (
                SigmaType::SOption(Box::new(tpe)),
                SigmaValue::Opt(Some(Box::new(v))),
            )
        }
        other => {
            return Err(BridgeError::Decode(format!(
                "unsupported input SValue kind: {other}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_sigma::evaluator::{sigma_to_value, EvalBox};
    use serde_json::json;

    /// A BoxEnv over dummy boxes — primitive round-trips never resolve it.
    fn with_env<R>(f: impl FnOnce(&BoxEnv<'_>) -> R) -> R {
        let b = EvalBox::simple(0, Vec::new());
        f(&BoxEnv { self_box: &b, inputs: &[], outputs: &[], data_inputs: &[] })
    }

    /// Round-trip a value-preserving SValue: JSON → (SigmaType, SigmaValue)
    /// → evaluator Value (the impl's own constant lowering) → JSON.
    fn roundtrip(j: J) {
        let (tpe, val) = decode_constant(&j).expect("decode");
        let v = sigma_to_value(&tpe, &val).expect("sigma_to_value");
        let back = with_env(|env| encode_value(&v, env)).expect("encode");
        assert_eq!(back, j, "round-trip mismatch");
    }

    #[test]
    fn rt_bool_and_numerics() {
        roundtrip(json!({"kind": "Boolean", "value": true}));
        roundtrip(json!({"kind": "Byte", "value": -128}));
        roundtrip(json!({"kind": "Short", "value": 32767}));
        roundtrip(json!({"kind": "Int", "value": -2147483648i64}));
    }

    #[test]
    fn rt_long_bigint_unsigned_are_strings() {
        roundtrip(json!({"kind": "Long", "value": "9223372036854775807"}));
        roundtrip(json!({"kind": "Long", "value": "-9223372036854775808"}));
        roundtrip(json!({"kind": "BigInt", "value": "-45"}));
        roundtrip(json!({"kind": "BigInt", "value": "123456789012345678901234567890"}));
        roundtrip(json!({"kind": "UnsignedBigInt", "value": "0"}));
        // 2^256 - 1: above the signed ceiling — valid unsigned.
        roundtrip(json!({
            "kind": "UnsignedBigInt",
            "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        }));
    }

    #[test]
    fn rt_colls_tuple_option() {
        roundtrip(json!({"kind": "Coll", "elem": {"tag": "SByte"}, "items": [
            {"kind": "Byte", "value": 0}, {"kind": "Byte", "value": 8}, {"kind": "Byte", "value": -45}]}));
        roundtrip(json!({"kind": "Coll", "elem": {"tag": "SInt"}, "items": [
            {"kind": "Int", "value": 1}, {"kind": "Int", "value": 2}]}));
        roundtrip(json!({"kind": "Tuple", "items": [
            {"kind": "Coll", "elem": {"tag": "SByte"}, "items": [{"kind": "Byte", "value": 1}]},
            {"kind": "Int", "value": 0}]}));
        roundtrip(json!({"kind": "Option", "value": {"kind": "Int", "value": 2}}));
    }

    #[test]
    fn rt_sigmaprop_groupelement_avltree() {
        roundtrip(json!({"kind": "SigmaProp", "raw_hex": "d3"})); // TrivialProp(true)
        roundtrip(json!({"kind": "SigmaProp",
            "raw_hex": "cd02288f0e55610c3355c89ed6c5de43cf20da145b8c54f03a29f481e540d94e9a69"}));
        roundtrip(json!({"kind": "GroupElement",
            "bytes_hex": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}));
        // Blessed AvlTreeData fixture (AvlTree_properties_equivalence input).
        roundtrip(json!({"kind": "AvlTree",
            "bytes_hex": "000183807f66b301530120ff7fc6bd6601ff01ff7f7d2bedbbffff00187fe8909406010101"}));
    }

    /// The Refused/Decode boundary: bytes the LIBRARY parses-and-rejects
    /// classify as Refused (its verdict → runner `errored`); JSON the bridge
    /// cannot dispatch classifies as Decode (bridge failure → `panicked`).
    #[test]
    fn refused_vs_decode_classification() {
        let r = decode_constant(&json!({"kind": "Box", "bytes_hex": "00"}));
        assert!(matches!(r, Err(BridgeError::Refused(_))), "got {r:?}");
        // SHeader: the impl's typed wire-reader refusal — Refused, not Decode.
        let h = decode_constant(&json!({"kind": "Header", "bytes_hex": "00"}));
        assert!(matches!(h, Err(BridgeError::Refused(_))), "got {h:?}");
        let d = decode_constant(&json!({"kind": "Nope", "value": 1}));
        assert!(matches!(d, Err(BridgeError::Decode(_))), "got {d:?}");
    }

    /// Every leaf tag in runner-contract §4 maps to its EXACT string both
    /// ways (no Debug fallback on encode, no "unsupported" on decode).
    #[test]
    fn stype_tag_map_total_over_contract_s4() {
        let leaves = [
            (SigmaType::SBoolean, "SBoolean"),
            (SigmaType::SByte, "SByte"),
            (SigmaType::SShort, "SShort"),
            (SigmaType::SInt, "SInt"),
            (SigmaType::SLong, "SLong"),
            (SigmaType::SBigInt, "SBigInt"),
            (SigmaType::SUnsignedBigInt, "SUnsignedBigInt"),
            (SigmaType::SGroupElement, "SGroupElement"),
            (SigmaType::SSigmaProp, "SSigmaProp"),
            (SigmaType::SBox, "SBox"),
            (SigmaType::SHeader, "SHeader"),
            (SigmaType::SPreHeader, "SPreHeader"),
            (SigmaType::SAvlTree, "SAvlTree"),
            (SigmaType::SUnit, "SUnit"),
            (SigmaType::SAny, "SAny"),
        ];
        for (t, tag) in leaves {
            assert_eq!(encode_stype(&t), json!({"tag": tag}), "encode {tag}");
            assert_eq!(decode_stype(&json!({"tag": tag})).expect(tag), t, "decode {tag}");
        }
        for j in [
            json!({"tag": "SColl", "elem": {"tag": "SAvlTree"}}),
            json!({"tag": "SOption", "elem": {"tag": "SAvlTree"}}),
            json!({"tag": "STuple", "items": [{"tag": "SInt"}, {"tag": "SAvlTree"}]}),
        ] {
            let t = decode_stype(&j).expect("recursive decode");
            assert_eq!(encode_stype(&t), j, "recursive round-trip");
        }
    }
}
