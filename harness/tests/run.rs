//! main_run end to end over a real SANTA checkout ($SANTA_DIR or the nearest ancestor holding vectors/grading.json),
//! with a runner function standing in for an implementation. A chain scope at v4 selects no bounded file, so the
//! bounded child (which re-invokes the runner binary) is not exercised here; the runners' board runs cover it.
use santa_harness::{main_run, selection};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn santa() -> PathBuf {
    if let Ok(d) = std::env::var("SANTA_DIR") {
        return PathBuf::from(d);
    }
    let mut d = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    loop {
        if d.join("vectors").join("grading.json").is_file() {
            return d;
        }
        if !d.pop() {
            panic!("no SANTA checkout above this crate: set SANTA_DIR");
        }
    }
}

fn temp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("santa-harness-run-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn runner_json(dir: &Path) -> PathBuf {
    let p = dir.join("runner.json");
    fs::write(&p, json!({"name": "t", "version": "v4", "tiers": ["chain"]}).to_string()).unwrap();
    p
}

/// A chain answer: the entry's `expected`, with `error: null` when it has none.
fn honest(_: &Path, doc: &Value) -> BTreeMap<String, Value> {
    doc["entries"].as_array().unwrap().iter().map(|e| {
        let mut a: Map<String, Value> = e["expected"].as_object().cloned().unwrap_or_default();
        a.entry("error".to_string()).or_insert(Value::Null);
        (e["name"].as_str().unwrap().to_string(), Value::Object(a))
    }).collect()
}

fn results(out: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(out.join("results.json")).unwrap()).unwrap()
}

#[test]
fn an_honest_runner_writes_results_the_schema_accepts() {
    let s = santa();
    let d = temp("honest");
    let out = d.join("out");
    main_run(&runner_json(&d), &s, &out, &honest).unwrap();
    let r = results(&out);
    let schema: Value = serde_json::from_str(&fs::read_to_string(s.join("schema/santa-runner-results.schema.json")).unwrap()).unwrap();
    let v = jsonschema::validator_for(&schema).unwrap();
    assert!(v.is_valid(&r), "{:?}", v.validate(&r).err().map(|e| e.to_string()));
    assert_eq!(r["totals"]["red"], 0);
    let head = Command::new("git").arg("-C").arg(&s).args(["rev-parse", "HEAD"]).output().unwrap();
    assert_eq!(r["santa"], String::from_utf8(head.stdout).unwrap().trim());
    let vectors = s.join("vectors");
    let scope = santa_harness::read_scope(&d.join("runner.json")).unwrap();
    let selected = selection::select(&selection::discover(&vectors).unwrap(), &vectors, &scope).unwrap();
    assert!(!selected.is_empty());
    for f in &selected {
        assert!(out.join("actuals").join(&f.rel).is_file(), "no actuals for {}", f.rel);
    }
    assert!(!out.join(".children").exists());
}

#[test]
fn a_skipped_entry_grades_red() {
    let s = santa();
    let d = temp("skipped");
    let out = d.join("out");
    let first: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    let skipping = |p: &Path, doc: &Value| {
        let mut m = honest(p, doc);
        let mut f = first.borrow_mut();
        if f.is_none() {
            let name = m.keys().next().unwrap().clone();
            m.remove(&name);
            *f = Some(name);
        }
        m
    };
    main_run(&runner_json(&d), &s, &out, &skipping).unwrap();
    let r = results(&out);
    assert_eq!(r["totals"]["red"], 1);
    let reds: Vec<&Value> = r["slices"].as_object().unwrap().values().flat_map(|sl| sl["red"].as_array().unwrap()).collect();
    assert_eq!(reds[0]["entry"], json!(first.borrow().clone().unwrap()));
    assert_eq!(reds[0]["dim"], "value", "a chain entry left unanswered is red on its value");
}

#[test]
fn a_wrong_oracle_stops_the_run() {
    let s = santa();
    let fake = temp("fake-santa");
    fs::create_dir_all(fake.join("vectors")).unwrap();
    fs::create_dir_all(fake.join("oracle")).unwrap();
    fs::copy(s.join("vectors/grading.json"), fake.join("vectors/grading.json")).unwrap();
    fs::copy(s.join("oracle/selection.json"), fake.join("oracle/selection.json")).unwrap();
    let mut doc: Value = serde_json::from_str(&fs::read_to_string(s.join("oracle/verdicts-grading.json")).unwrap()).unwrap();
    doc["cases"][0]["verdict"] = json!({"outcome": "panicked"});
    doc["cases"][1]["verdict"] = json!({"outcome": "not-implemented"});
    fs::write(fake.join("oracle/verdicts-grading.json"), doc.to_string()).unwrap();
    let d = temp("wrong-oracle");
    let out = d.join("out");
    assert!(main_run(&runner_json(&d), &fake, &out, &honest).is_err());
    assert!(!out.join("results.json").exists());
}

/// The bounded path end to end: the fixture binary (src/bin/santa-harness-fixture.rs, an honest runner) runs as `run`
/// and re-invokes itself as `one` for every bounded file, under the watchdog.
#[test]
fn bounded_files_run_as_children_of_the_runner() {
    let s = santa();
    let d = temp("bounded");
    let rj = d.join("runner.json");
    fs::write(&rj, json!({"version": "v6", "tiers": ["eval"]}).to_string()).unwrap();
    let out = d.join("out");
    let st = Command::new(env!("CARGO_BIN_EXE_santa-harness-fixture")).arg("run").arg(&rj).arg(&s).arg(&out).status().unwrap();
    assert!(st.success());
    let r = results(&out);
    let bounded = "eval/v6/authored/Global.serialize_shared_nested_bounded_G_size_only_32768x4096.json";
    let a: Value = serde_json::from_str(&fs::read_to_string(out.join("actuals").join(bounded)).unwrap()).unwrap();
    assert!(a.as_object().is_some_and(|m| !m.is_empty() && m.values().all(|x| x.get("error").is_some_and(|e| e != "exceeded" && e != "panicked"))), "{a}");
    assert_eq!(r["totals"]["red"], 0, "an honest runner is all nice, its bounded files run as children");
}
