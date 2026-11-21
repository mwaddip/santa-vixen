//! A test fixture, not a SANTA runner: an honest runner (it answers every entry with its `expected`) driven through the
//! harness, so the harness's tests can run `run` and the bounded `one` child end to end.
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn honest(_: &Path, doc: &Value) -> BTreeMap<String, Value> {
    doc["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            let mut a: Map<String, Value> = e["expected"].as_object().cloned().unwrap_or_default();
            a.entry("error".to_string()).or_insert(Value::Null);
            (e["name"].as_str().unwrap_or("").to_string(), Value::Object(a))
        })
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r = match a.get(1).map(String::as_str) {
        Some("run") if a.len() == 5 => santa_harness::main_run(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]), &honest),
        Some("one") if a.len() == 5 => santa_harness::main_one(Path::new(&a[2]), &a[3], Path::new(&a[4]), &honest),
        _ => Err("usage: santa-harness-fixture run <runner.json> <santa-dir> <out-dir> | one <santa-dir> <relpath> <out-file>".into()),
    };
    if let Err(e) = r {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
