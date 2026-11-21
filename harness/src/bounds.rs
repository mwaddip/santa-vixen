//! The bounded-file watchdog (runner-integration §3a): a bounded file's entry runs in a child process in a process
//! group of its own (setpgid, never a new session), under an RLIMIT_DATA backstop; the parent polls the group's
//! resident memory (VmRSS + VmSwap) and each process's peak (VmHWM) every 10 ms, and kills the group past
//! `memory_mb`, or past `wall_s`. A child that finished and reported its own peak past the budget is exceeded too: a
//! spike between two polls counts, as a cgroup bound would have killed it there.
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

/// The envelope's `limits`: None for an ordinary file, Err for a `limits` that is not a positive `memory_mb` and
/// `wall_s` (never run such a file unbounded).
pub fn budget(doc: &Value) -> Result<Option<Budget>, String> {
    let Some(l) = doc.get("limits") else { return Ok(None) };
    match (l["memory_mb"].as_u64(), l["wall_s"].as_u64()) {
        (Some(m), Some(w)) if m > 0 && w > 0 => Ok(Some(Budget { memory_mb: m, wall_s: w })),
        _ => Err(format!("a malformed `limits`: {l}")),
    }
}

/// How a bounded child ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It exited 0 within its budget: its actuals are what it wrote.
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

/// A process group's memory (KiB): `now_kib` = VmRSS + VmSwap summed over its processes, `peak_kib` = the highest
/// VmHWM of any of them (a spike already over still shows; after exec a process's VmHWM counts only its own memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    pub now_kib: u64,
    pub peak_kib: u64,
}

/// The memory of the process group `pgid`, in one pass over /proc.
pub fn group_memory(pgid: i32) -> Memory {
    let mut m = Memory { now_kib: 0, peak_kib: 0 };
    for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // after the command's ")": state, ppid, pgrp
        let f: Vec<&str> = stat.rsplit_once(')').map(|(_, r)| r.split_whitespace().collect()).unwrap_or_default();
        if f.len() < 3 || f[2].parse::<i32>().ok() != Some(pgid) {
            continue;
        }
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
        let kib = |l: &str| l.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        for l in status.lines() {
            if l.starts_with("VmRSS:") || l.starts_with("VmSwap:") {
                m.now_kib += kib(l);
            } else if l.starts_with("VmHWM:") {
                m.peak_kib = m.peak_kib.max(kib(l));
            }
        }
    }
    m
}

fn kill_group(pgid: i32) {
    // SAFETY: signalling the process group this module created.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// Whether `pid` has ended, without reaping it (WNOWAIT): while its zombie holds the pid, the group id cannot be
/// reused, so the group is killed before the child is reaped.
fn ended(pid: i32) -> bool {
    // SAFETY: waitid writes only into the local siginfo.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT);
        r == 0 && info.si_pid() != 0
    }
}

/// Reaps `pid`: its wait status.
fn reap(pid: i32) -> std::process::ExitStatus {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid writes only into the local.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    std::process::ExitStatus::from_raw(status)
}

/// Runs `cmd` as a bounded child: its own process group, the backstop, stderr to `stderr` (read for the runtime's
/// out-of-memory signature), the group killed past the budget or once the child ends. A child that finishes and
/// wrote its own peak resident size (KiB) to `peak_report` past the budget is exceeded too: its parent cannot learn
/// it otherwise (a forked child's rusage carries the parent's memory at the fork).
pub fn run_child(mut cmd: Command, b: &Budget, stderr: &Path, peak_report: Option<&Path>) -> Outcome {
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
    // the child is reaped here (waitid, waitpid), never through the handle
    let child = match cmd.stdin(Stdio::null()).stderr(err).spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Crashed(format!("cannot start the bounded child: {e}")),
    };
    let pgid = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(b.wall_s);
    let over = |kib: u64| kib > b.memory_mb * 1024;
    loop {
        if ended(pgid) {
            kill_group(pgid);
            let status = reap(pgid);
            if status.success() {
                let reported = peak_report.and_then(|p| fs::read_to_string(p).ok()).and_then(|t| t.trim().parse::<u64>().ok());
                return if reported.is_some_and(over) { Outcome::Exceeded("memory") } else { Outcome::Finished };
            }
            let said = fs::read_to_string(stderr).unwrap_or_default();
            if status.signal() == Some(libc::SIGABRT) && said.contains("memory allocation of") {
                return Outcome::Exceeded("memory");
            }
            return Outcome::Crashed(match status.signal() {
                Some(sig) => format!("process killed by signal {sig}"),
                None => format!("process exit status {}", status.code().unwrap_or(-1)),
            });
        }
        let m = group_memory(pgid);
        if over(m.now_kib) || over(m.peak_kib) {
            kill_group(pgid);
            reap(pgid);
            return Outcome::Exceeded("memory");
        }
        if Instant::now() >= deadline {
            kill_group(pgid);
            reap(pgid);
            return Outcome::Exceeded("time");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
