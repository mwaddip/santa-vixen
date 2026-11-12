//! Context bindings (runner contract §4). A binding is an SValue — decoded by
//! [`sval::decode_constant`] — or `{"kind":"Value","bytes_hex":…}`: the bytes a node itself reads
//! for that position, read here by arkadianet's OWN reader for it and never rebuilt from an
//! SValue. The reader refusing them (a parse error, rule 1019's v6-type gate, bytes left over) is
//! [`BridgeError::Refused`], which every caller maps to `errored`: a node would reject the
//! transaction.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_ser::input::read_context_extension;
use ergo_ser::register::{read_registers, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use serde_json::Value as J;

use crate::sval::{self, BridgeError};

/// A `Value` binding's bytes, or `None` for an SValue.
fn value_bytes(j: &J) -> Option<Result<Vec<u8>, BridgeError>> {
    if j.get("kind").and_then(|k| k.as_str()) != Some("Value") {
        return None;
    }
    Some(match j.get("bytes_hex").and_then(|h| h.as_str()) {
        Some(h) => sval::hex_decode(h),
        None => Err(BridgeError::Decode("Value binding without bytes_hex".into())),
    })
}

/// Read `frame` whole with `parse` under the entry's activated version — what a node parses a
/// block's transactions under from block version 4 (ergo `BlockTransactions.scala:195`,
/// `Header.scala:154` at v6.0.7). A reader error, or bytes left after the value, is the reader
/// refusing the binding.
fn read_whole<T>(
    frame: &[u8],
    activated: u8,
    parse: impl FnOnce(&mut VlqReader<'_>) -> Result<T, ReadError>,
) -> Result<T, BridgeError> {
    let mut r = VlqReader::new(frame).with_activated_script_version(activated);
    let out = parse(&mut r)
        .map_err(|e| BridgeError::Refused(format!("the reader refused the Value: {e}")))?;
    if r.position() != frame.len() {
        return Err(BridgeError::Refused(format!(
            "{} byte(s) left after the value",
            frame.len() - r.position()
        )));
    }
    Ok(out)
}

/// A binding at an extension position: var 1 (v2/v4 `input`), a v3 / v5 / full-context extension
/// value. A `Value` is read by arkadianet's `read_context_extension`, framed as the one-variable
/// extension `01 01 <bytes>` — the count, then a dummy id: the binding's key is the vector's and
/// the caller applies it, so a v5 key >= 0x80 still reaches the context the way the key-domain
/// vectors need.
pub fn extension_binding(j: &J, activated: u8) -> Result<(SigmaType, SigmaValue), BridgeError> {
    let Some(bytes) = value_bytes(j) else {
        return sval::decode_constant(j);
    };
    let frame = [&[0x01u8, 0x01][..], &bytes?].concat();
    let mut ext = read_whole(&frame, activated, read_context_extension)?;
    ext.values
        .shift_remove(&1u8)
        .ok_or_else(|| BridgeError::Refused("the extension reader returned no variable".into()))
}

/// A binding at a register position (`selfRegisters`). A `Value` is read by arkadianet's
/// `read_registers`, framed as the one-register block `01 <bytes>`; the result is the reader's own
/// entry.
pub fn register_binding(j: &J, activated: u8) -> Result<RegisterValue, BridgeError> {
    let Some(bytes) = value_bytes(j) else {
        let (tpe, value) = sval::decode_constant(j)?;
        return Ok(RegisterValue { tpe, value });
    };
    let frame = [&[0x01u8][..], &bytes?].concat();
    let regs = read_whole(&frame, activated, read_registers)?;
    regs.registers
        .into_iter()
        .next()
        .ok_or_else(|| BridgeError::Refused("the register reader returned no R4".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::sigma_value::read_constant;
    use serde_json::json;

    fn value_json(bytes_hex: &str) -> J {
        json!({ "kind": "Value", "bytes_hex": bytes_hex })
    }
    // Long 7: type 0x05, then zig-zag 14.
    const LONG_7: &str = "050e";

    #[test]
    fn an_extension_value_equals_the_json_form_of_the_same_value() {
        let from_json = extension_binding(&json!({ "kind": "Long", "value": "7" }), 3).unwrap();
        assert_eq!(extension_binding(&value_json(LONG_7), 3).unwrap(), from_json);
    }

    #[test]
    fn a_register_value_equals_the_json_form_of_the_same_value() {
        let from_json = register_binding(&json!({ "kind": "Long", "value": "7" }), 3).unwrap();
        assert_eq!(register_binding(&value_json(LONG_7), 3).unwrap(), from_json);
    }

    #[test]
    fn bytes_left_after_the_value_are_refused_at_both_positions() {
        let trailing = value_json(&format!("{LONG_7}00"));
        for got in [
            extension_binding(&trailing, 3).map(|_| ()),
            register_binding(&trailing, 3).map(|_| ()),
        ] {
            match got {
                Err(BridgeError::Refused(m)) => assert!(m.contains("left after the value"), "{m}"),
                other => panic!("expected the leftover-bytes refusal, got {other:?}"),
            }
        }
    }

    // Rule 1019: an Option-typed value (`Option[Int]` Some(1): type 0x24|0x04 = 0x28, then 01 =
    // Some, then Int 1 zig-zag = 02) is refused by both of a node's readers at every version.
    #[test]
    fn rule_1019_refuses_an_option_at_both_positions() {
        // The bytes ARE an Option[Int] constant — a plain constant read at v3 takes them — so the
        // refusals below are rule 1019's, not a parse error's.
        let mut r = VlqReader::new(&[0x28, 0x01, 0x02]).with_activated_script_version(3);
        let (tpe, _) = read_constant(&mut r).expect("an Option[Int] constant");
        assert_eq!(tpe, SigmaType::SOption(Box::new(SigmaType::SInt)));
        let some_int = value_json("280102");
        assert!(matches!(extension_binding(&some_int, 3), Err(BridgeError::Refused(_))));
        assert!(matches!(register_binding(&some_int, 3), Err(BridgeError::Refused(_))));
    }

    // A Tuple EXPRESSION (opcode 0x86, two items: Int 1, Int 2) — what the JVM's `getValue` takes
    // at both positions. Whatever arkadianet's readers answer is surfaced as it is; this pins that
    // the adapter hands the bytes to them rather than refusing first.
    #[test]
    fn a_tuple_expression_reaches_both_readers() {
        let tuple_expr = value_json("860204020404");
        let reg = register_binding(&tuple_expr, 3).expect("arkadianet's register reader takes it");
        assert!(matches!(reg.tpe, SigmaType::STuple(_)), "got {reg:?}");
        let ext = extension_binding(&tuple_expr, 3);
        assert!(!matches!(ext, Err(BridgeError::Decode(_))), "got {ext:?}");
    }
}
