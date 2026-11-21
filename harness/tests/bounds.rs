//! The bounded-file watchdog (runner-integration §3a): a child in its own process group, killed at its memory or wall
//! budget, its crash described. Children run as `bash <script>`: executing a just-written script races with other test
//! threads' forks ("text file busy").
use santa_harness::bounds::{budget, run_child, Budget, Outcome};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn script(tag: &str, body: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("santa-harness-bounds-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let s = d.join("run.sh");
    fs::write(&s, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
    s
}

fn run(s: &Path, memory_mb: u64, wall_s: u64) -> Outcome {
    let mut cmd = Command::new("bash");
    cmd.arg(s);
    run_child(cmd, &Budget { memory_mb, wall_s }, &s.with_file_name("stderr"))
}

fn alive(pid: &str) -> bool {
    fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
        .map(|st| !st.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'))
        .unwrap_or(false)
}

#[test]
fn a_child_past_its_wall_time_is_exceeded_time() {
    let t0 = Instant::now();
    assert_eq!(run(&script("wall", "sleep 30"), 1024, 1), Outcome::Exceeded("time"));
    assert!(t0.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_child_past_its_memory_is_exceeded_memory() {
    let s = script("memory", "exec python3 -I -c 'a = []\nwhile True: a.append(bytearray(10**7))'");
    assert_eq!(run(&s, 64, 30), Outcome::Exceeded("memory"));
}

#[test]
fn a_childs_grandchild_dies_with_its_group() {
    let s = script("group", "sleep 30 &\necho $! > \"$(dirname \"$0\")/child.pid\"\nsleep 30");
    assert_eq!(run(&s, 1024, 1), Outcome::Exceeded("time"));
    std::thread::sleep(Duration::from_millis(200));
    let pid = fs::read_to_string(s.with_file_name("child.pid")).unwrap();
    assert!(!alive(&pid), "the grandchild {} outlived its group", pid.trim());
}

#[test]
fn a_crash_is_its_exit_status() {
    assert_eq!(run(&script("exit", "exit 101"), 1024, 30), Outcome::Crashed("process exit status 101".into()));
    assert_eq!(run(&script("segv", "kill -SEGV $$"), 1024, 30), Outcome::Crashed("process killed by signal 11".into()));
}

#[test]
fn a_refused_allocation_abort_is_memory() {
    let s = script("abort", "echo 'memory allocation of 1073741824 bytes failed' >&2\nkill -ABRT $$");
    assert_eq!(run(&s, 1024, 30), Outcome::Exceeded("memory"));
}

#[test]
fn a_clean_child_finishes() {
    assert_eq!(run(&script("ok", "true"), 1024, 30), Outcome::Finished);
}

#[test]
fn a_budget_is_the_envelopes_limits() {
    assert_eq!(budget(&json!({"limits": {"memory_mb": 1280, "wall_s": 10}})), Some(Budget { memory_mb: 1280, wall_s: 10 }));
    assert_eq!(budget(&json!({"entries": []})), None);
}
