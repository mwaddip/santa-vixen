//! The bounded-file watchdog (runner-integration §3a): a bounded file's entry runs in a child process in a process
//! group of its own (setpgid, never a new session), under an RLIMIT_DATA backstop; the parent polls the group's
//! resident memory (VmRSS + VmSwap) every 10 ms and kills the group past `memory_mb`, or past `wall_s`.
use serde_json::Value;
use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A bounded file's budget: memory in MiB, wall-clock time in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub memory_mb: u64,
    pub wall_s: u64,
}

/// The envelope's `limits`, when the file is bounded.
pub fn budget(doc: &Value) -> Option<Budget> {
    let l = doc.get("limits")?;
    Some(Budget { memory_mb: l["memory_mb"].as_u64()?, wall_s: l["wall_s"].as_u64()? })
}

/// How a bounded child ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It exited 0: its actuals are what it wrote.
    Finished,
    /// It went over its budget: `"memory"` or `"time"`.
    Exceeded(&'static str),
    /// It ended otherwise: the note (`process exit status N`, `process killed by signal N`, or why it could not start).
    Crashed(String),
}

/// The backstop under the watchdog: a burst between two polls stops here (twice the budget, at least 4096 MiB).
fn backstop_mb(b: &Budget) -> u64 {
    (2 * b.memory_mb).max(4096)
}

/// The resident memory of the process group `pgid` (KiB): VmRSS + VmSwap of every process in it.
fn group_kib(pgid: i32) -> u64 {
    let mut total = 0;
    for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // after the command's ")": state, ppid, pgrp
        let f: Vec<&str> = stat.rsplit_once(')').map(|(_, r)| r.split_whitespace().collect()).unwrap_or_default();
        if f.len() < 3 || f[2].parse::<i32>().ok() != Some(pgid) {
            continue;
        }
        if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmSwap:") {
                    total += line.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
                }
            }
        }
    }
    total
}

fn kill_group(pgid: i32) {
    // SAFETY: signalling the process group this module created.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// Runs `cmd` as a bounded child: its own process group, the backstop, stderr to `stderr` (read for the runtime's
/// out-of-memory signature), the group killed past the budget or after it exits.
pub fn run_child(mut cmd: Command, b: &Budget, stderr: &Path) -> Outcome {
    let err = match fs::File::create(stderr) {
        Ok(f) => f,
        Err(e) => return Outcome::Crashed(format!("cannot open {}: {e}", stderr.display())),
    };
    let bytes = (backstop_mb(b) * 1024 * 1024) as libc::rlim_t;
    // SAFETY: setpgid and setrlimit are async-signal-safe; the closure allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let lim = libc::rlimit { rlim_cur: bytes, rlim_max: bytes };
            if libc::setrlimit(libc::RLIMIT_DATA, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match cmd.stdin(Stdio::null()).stderr(err).spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Crashed(format!("cannot start the bounded child: {e}")),
    };
    let pgid = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(b.wall_s);
    let over = |kib: u64| kib > b.memory_mb * 1024;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                kill_group(pgid);
                if status.success() {
                    return Outcome::Finished;
                }
                let said = fs::read_to_string(stderr).unwrap_or_default();
                if said.contains("memory allocation of") {
                    return Outcome::Exceeded("memory");
                }
                return Outcome::Crashed(match status.signal() {
                    Some(sig) => format!("process killed by signal {sig}"),
                    None => format!("process exit status {}", status.code().unwrap_or(-1)),
                });
            }
            Ok(None) => {}
            Err(e) => {
                kill_group(pgid);
                return Outcome::Crashed(format!("cannot wait for the bounded child: {e}"));
            }
        }
        if over(group_kib(pgid)) {
            kill_group(pgid);
            let _ = child.wait();
            return Outcome::Exceeded("memory");
        }
        if Instant::now() >= deadline {
            kill_group(pgid);
            let _ = child.wait();
            return Outcome::Exceeded("time");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
