//! The harness's self-checks against a SANTA checkout: `$SANTA_DIR`, or the nearest ancestor of this crate holding
//! `vectors/grading.json` (a runner checked out as SANTA's submodule). Never skipped.
use santa_harness::{grading::Grading, oracle, read_scope, santa_commit};
use serde_json::{json, Value};
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

fn grading(santa: &Path) -> Grading {
    let doc: Value = serde_json::from_str(&fs::read_to_string(santa.join("vectors/grading.json")).unwrap()).unwrap();
    Grading::parse(&doc).unwrap()
}

fn temp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("santa-harness-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn the_verdict_and_selection_oracles_are_reproduced() {
    let s = santa();
    oracle::check(&s, &grading(&s)).unwrap();
}

#[test]
fn a_wrong_verdict_is_named() {
    let s = santa();
    let fake = temp("wrong-verdict");
    fs::create_dir_all(fake.join("oracle")).unwrap();
    fs::copy(s.join("oracle/selection.json"), fake.join("oracle/selection.json")).unwrap();
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(s.join("oracle/verdicts-grading.json")).unwrap()).unwrap();
    let case = doc["cases"][0].clone();
    doc["cases"][0]["verdict"] = json!({"outcome": "not-implemented"});
    if case["verdict"] == doc["cases"][0]["verdict"] {
        doc["cases"][0]["verdict"] = json!({"outcome": "panicked"});
    }
    fs::write(fake.join("oracle/verdicts-grading.json"), doc.to_string()).unwrap();
    let e = oracle::check(&fake, &grading(&s)).unwrap_err();
    assert!(e.contains(case["name"].as_str().unwrap()), "{e}");
}

#[test]
fn an_unknown_oracle_schema_is_refused() {
    let s = santa();
    let fake = temp("unknown-oracle");
    fs::create_dir_all(fake.join("oracle")).unwrap();
    fs::write(fake.join("oracle/x.json"), json!({"schema": "santa-oracle-foo/v1", "cases": []}).to_string()).unwrap();
    let e = oracle::check(&fake, &grading(&s)).unwrap_err();
    assert!(e.contains("santa-oracle-foo/v1"), "{e}");
}

#[test]
fn the_santa_commit_follows_real_paths() {
    let s = santa();
    let out = Command::new("git").arg("-C").arg(&s).args(["rev-parse", "HEAD"]).output().unwrap();
    let head = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(santa_commit(&s), Some(head.clone()));
    assert_eq!(santa_commit(&s.join("vectors").join("..")), Some(head));
    assert_eq!(santa_commit(&temp("not-git")), None);
}

#[test]
fn read_scope_refuses_what_conform_refuses() {
    let d = temp("scope");
    let p = d.join("runner.json");
    let scope = |j: Value| {
        fs::write(&p, j.to_string()).unwrap();
        read_scope(&p)
    };
    for bad in [
        json!({"version": "v6", "tiers": []}),
        json!({"version": "v6", "tiers": ["evil"]}),
        json!({"version": "v6", "tiers": ["eval", "eval"]}),
        json!({"version": "v6", "tiers": ["wire"], "kinds": ["Box", "Box"]}),
        json!({"version": "v6", "tiers": ["eval"], "kinds": ["Box"]}),
        json!({"version": "any", "tiers": ["eval"]}),
        json!({"version": "v6", "tiers": ["wire"], "kinds": []}),
        json!({"version": "v6", "tiers": ["wire"], "kinds": ["Boxes"]}),
        json!({"version": "v6", "tiers": ["eval"], "activations": false}),
    ] {
        assert!(scope(bad.clone()).is_err(), "accepted {bad}");
    }
    let sc = scope(json!({"name": "x", "label": "x", "impl": null, "version": "v6", "tiers": ["eval", "wire"]})).unwrap();
    assert!(sc.cost && sc.activation && sc.kinds.is_none());
    assert_eq!(sc.tiers, vec!["eval".to_string(), "wire".to_string()]);
}
