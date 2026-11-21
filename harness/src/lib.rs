//! santa-harness — what a Rust SANTA runner needs besides its implementation (SANTA's runner-integration §3, §3a, §4):
//! the grading interpreter (a copy of SANTA's santa-check), selection, the oracle self-checks, the bounded-file
//! watchdog and the results it writes. It reads a SANTA checkout as data only. A copy of this crate lives in each Rust
//! runner SANTA maintains (blitzen, donner, vixen); keep the copies identical.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

pub mod bounds;
pub mod equal;
pub mod grading;
pub mod oracle;
pub mod results;
pub mod selection;

pub use equal::structural_equal;

/// The version slots, ordered; a runner's `version` selects its slot and every lower one.
pub const VERSIONS: [&str; 3] = ["v4", "v5", "v6"];
/// SANTA's tiers.
pub const TIERS: [&str; 7] = ["eval", "wire", "transaction", "block", "chain", "authds", "nipopow"];
/// The wire kinds (the wire vector schema's `kind` enum).
pub const WIRE_KINDS: [&str; 7] = ["Constant", "Box", "Transaction", "Header", "SigmaBoolean", "ErgoTree", "BlockTransactions"];

/// What a runner declares it implements (runner-integration §2): it decides which vector files the runner grades.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub version: String,
    pub tiers: Vec<String>,
    /// Whether the runner claims the cost dimension (default true).
    pub cost: bool,
    /// The wire kinds it implements; None = every kind.
    pub kinds: Option<Vec<String>>,
    /// Whether it applies the rules tied to the activated script version (default true).
    pub activation: bool,
}

/// The scope keys of a runner.json (any other key, such as SANTA's `name` or `impl`, is ignored). Refused as SANTA's
/// conform refuses them: an unknown version; empty, unknown or repeated tiers; empty, unknown or repeated kinds, or
/// kinds without the wire tier; a flag that is not a boolean.
pub fn parse_scope(j: &Value) -> Result<Scope, String> {
    let version = j["version"].as_str().ok_or("runner.json: no \"version\"")?.to_string();
    if !VERSIONS.contains(&version.as_str()) {
        return Err(format!("runner.json: unknown version {version:?}; known: {VERSIONS:?}"));
    }
    let names = |k: &str| -> Result<Vec<String>, String> {
        j[k].as_array()
            .ok_or(format!("runner.json: {k:?} is not an array"))?
            .iter()
            .map(|t| t.as_str().map(String::from).ok_or(format!("runner.json: a {k} entry is not a string")))
            .collect()
    };
    let distinct = |xs: &[String], known: &[&str], what: &str| -> Result<(), String> {
        if xs.is_empty() {
            return Err(format!("runner.json: {what} is empty"));
        }
        for (i, x) in xs.iter().enumerate() {
            if !known.contains(&x.as_str()) {
                return Err(format!("runner.json: unknown {what} {x:?}"));
            }
            if xs[..i].contains(x) {
                return Err(format!("runner.json: {what} {x:?} listed twice"));
            }
        }
        Ok(())
    };
    let tiers = names("tiers")?;
    distinct(&tiers, &TIERS, "tier")?;
    let kinds = match j.get("kinds") {
        None | Some(Value::Null) => None,
        Some(_) => {
            let ks = names("kinds")?;
            distinct(&ks, &WIRE_KINDS, "wire kind")?;
            if !tiers.iter().any(|t| t == "wire") {
                return Err("runner.json: \"kinds\" declared without the wire tier".into());
            }
            Some(ks)
        }
    };
    let flag = |k: &str| match j.get(k) {
        None => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(v) => Err(format!("runner.json: {k:?} is {v}, not a boolean")),
    };
    Ok(Scope { version, tiers, cost: flag("cost")?, kinds, activation: flag("activation")? })
}

/// The runner's scope, from its runner.json.
pub fn read_scope(runner_json: &Path) -> Result<Scope, String> {
    let text = fs::read_to_string(runner_json).map_err(|e| format!("{}: {e}", runner_json.display()))?;
    let j: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", runner_json.display()))?;
    parse_scope(&j)
}

/// The SANTA commit graded against: `git rev-parse HEAD` in `santa`, when `santa` is the top of its git checkout,
/// compared as real paths (runner-integration §4.3); otherwise None.
pub fn santa_commit(santa: &Path) -> Option<String> {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(santa)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let top = git(&["rev-parse", "--show-toplevel"])?;
    if fs::canonicalize(&top).ok()? != fs::canonicalize(santa).ok()? {
        return None;
    }
    git(&["rev-parse", "HEAD"])
}

/// The runner's function: a vector file's path and parsed document → its actuals by entry name, every outcome in the
/// tier's actuals shape (the harness adds nothing to them).
pub type RunFile<'a> = &'a dyn Fn(&Path, &Value) -> BTreeMap<String, Value>;

fn read_json(p: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))
}

fn write_json(p: &Path, v: &Value) -> Result<(), String> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    fs::write(p, serde_json::to_string_pretty(v).unwrap()).map_err(|e| format!("{}: {e}", p.display()))
}

/// The same actual for every entry of `doc`.
fn each_entry(doc: &Value, a: Value) -> BTreeMap<String, Value> {
    doc["entries"].as_array().into_iter().flatten().filter_map(|e| e["name"].as_str()).map(|n| (n.to_string(), a.clone())).collect()
}

/// A bounded file, run as the runner's own child (`<this binary> one <santa> <rel> <out-file>`) under its budget.
fn run_bounded(santa: &Path, f: &selection::VectorFile, doc: &Value, b: &bounds::Budget, dir: &Path, n: usize) -> BTreeMap<String, Value> {
    let out_file = dir.join(format!("{n}.json"));
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return each_entry(doc, json!({"error": "panicked", "note": format!("cannot find this runner's binary: {e}")})),
    };
    let mut cmd = Command::new(exe);
    cmd.arg("one").arg(santa).arg(&f.rel).arg(&out_file);
    match bounds::run_child(cmd, b, &dir.join(format!("{n}.stderr"))) {
        bounds::Outcome::Finished => match read_json(&out_file) {
            Ok(Value::Object(m)) => m.into_iter().collect(),
            _ => each_entry(doc, json!({"error": "panicked", "note": "the bounded child wrote no actuals"})),
        },
        bounds::Outcome::Exceeded(limit) => each_entry(doc, json!({"error": "exceeded", "limit": limit})),
        bounds::Outcome::Crashed(note) => each_entry(doc, json!({"error": "panicked", "note": note})),
    }
}

/// `<bin> run <runner.json> <santa-dir> <out-dir>` (runner-integration §3): read the scope, check both oracles, select,
/// run every selected file (a bounded one as a child under its budget, the rest through `run_file`), write
/// `actuals/<rel>`, grade every entry, write `results.json`, print a line per slice. Err: the runner could not run.
pub fn main_run(runner_json: &Path, santa: &Path, out: &Path, run_file: RunFile) -> Result<(), String> {
    let scope = read_scope(runner_json)?;
    let grading = grading::Grading::parse(&read_json(&santa.join("vectors").join("grading.json"))?)
        .map_err(|e| format!("vectors/grading.json: {e}"))?;
    oracle::check(santa, &grading)?;
    let vectors = santa.join("vectors");
    let files = selection::select(&selection::discover(&vectors)?, &vectors, &scope)?;
    let children = out.join(".children");
    fs::create_dir_all(&children).map_err(|e| format!("{}: {e}", children.display()))?;
    let mut tally = results::Tally::default();
    for (n, f) in files.iter().enumerate() {
        let path = vectors.join(&f.rel);
        let doc = read_json(&path)?;
        let actuals = match bounds::budget(&doc) {
            Some(b) => run_bounded(santa, f, &doc, &b, &children, n),
            None => run_file(&path, &doc),
        };
        write_json(&out.join("actuals").join(&f.rel), &json!(actuals))?;
        let label = grading.label_for(&f.tier, &doc).map_err(|e| format!("vectors/{}: {e}", f.rel))?;
        tally.add_file(f);
        for e in doc["entries"].as_array().into_iter().flatten() {
            let actual = e["name"].as_str().and_then(|n| actuals.get(n));
            let input = grading::Input { entry: e, actual, file: &doc, claims_cost: scope.cost };
            let v = grading.grade(label, &input).map_err(|err| format!("vectors/{}: {err}", f.rel))?;
            tally.add_verdict(f, e, actual, &v);
        }
    }
    let _ = fs::remove_dir_all(&children);
    write_json(&out.join("results.json"), &tally.results_json(santa_commit(santa), &scope))?;
    for line in tally.summary() {
        println!("{line}");
    }
    Ok(())
}

/// `<bin> one <santa-dir> <relpath> <out-file>`: a bounded file's child runs that one file and writes its actuals.
pub fn main_one(santa: &Path, rel: &str, out_file: &Path, run_file: RunFile) -> Result<(), String> {
    let path = santa.join("vectors").join(rel);
    let doc = read_json(&path)?;
    write_json(out_file, &json!(run_file(&path, &doc)))
}
