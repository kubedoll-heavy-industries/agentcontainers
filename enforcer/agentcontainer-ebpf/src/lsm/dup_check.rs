//! Kprobe on dup2 to detect reverse shell patterns.
//!
//! Reverse shells typically dup2() a socket fd onto stdin (0) and stdout (1)
//! inside a shell process. This hook detects that pattern:
//! 1. Check cgroup scoping -- skip non-enforced cgroups.
//! 2. Read REVERSE_SHELL_MODE: 0=enforce, 1=log-only, 2=off.
//! 3. If newfd > 1, skip (only stdin/stdout redirection is suspicious).
//! 4. Check if current comm is a known shell/interpreter.
//! 5. Emit event to REVERSE_SHELL_EVENTS ring buffer.
//! 6. In enforce mode, send SIGKILL via bpf_send_signal(9).

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_send_signal,
};
use aya_ebpf::macros::kprobe;
use aya_ebpf::programs::ProbeContext;

use agentcontainer_common::events::{ReverseShellEvent, COMM_MAX};

use crate::maps::{REVERSE_SHELL_EVENTS, REVERSE_SHELL_MODE};

// ---------------------------------------------------------------------------
// Reverse shell mode constants
// ---------------------------------------------------------------------------

const MODE_ENFORCE: u8 = 0;
const _MODE_LOG: u8 = 1;
const MODE_OFF: u8 = 2;

// ---------------------------------------------------------------------------
// Known shell/interpreter names (null-padded to COMM_MAX = 16 bytes)
// ---------------------------------------------------------------------------

const SHELL_SH: [u8; COMM_MAX] = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_BASH: [u8; COMM_MAX] = *b"bash\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_DASH: [u8; COMM_MAX] = *b"dash\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_ZSH: [u8; COMM_MAX] = *b"zsh\0\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_PYTHON: [u8; COMM_MAX] = *b"python\0\0\0\0\0\0\0\0\0\0";
const SHELL_PYTHON3: [u8; COMM_MAX] = *b"python3\0\0\0\0\0\0\0\0\0";
const SHELL_PERL: [u8; COMM_MAX] = *b"perl\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_RUBY: [u8; COMM_MAX] = *b"ruby\0\0\0\0\0\0\0\0\0\0\0\0";
const SHELL_NODE: [u8; COMM_MAX] = *b"node\0\0\0\0\0\0\0\0\0\0\0\0";

const KNOWN_SHELLS: [[u8; COMM_MAX]; 9] = [
    SHELL_SH,
    SHELL_BASH,
    SHELL_DASH,
    SHELL_ZSH,
    SHELL_PYTHON,
    SHELL_PYTHON3,
    SHELL_PERL,
    SHELL_RUBY,
    SHELL_NODE,
];

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

/// Check if the current cgroup is enforced. Returns true if enforcement applies.
#[inline(always)]
fn is_enforced_cgroup() -> bool {
    crate::maps::enforced_cgroup_for_current().is_some()
}

/// Compare two comm buffers byte-by-byte up to the first null in `pattern`.
#[inline(always)]
fn comm_matches(comm: &[u8; COMM_MAX], pattern: &[u8; COMM_MAX]) -> bool {
    let mut i = 0;
    while i < COMM_MAX {
        if comm[i] != pattern[i] {
            return false;
        }
        // If we hit a null in the pattern, the prefix matched.
        if pattern[i] == 0 {
            return true;
        }
        i += 1;
    }
    true
}

/// Check if the given comm matches any known shell/interpreter.
#[inline(always)]
fn is_known_shell(comm: &[u8; COMM_MAX]) -> bool {
    let mut i = 0;
    while i < KNOWN_SHELLS.len() {
        if comm_matches(comm, &KNOWN_SHELLS[i]) {
            return true;
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// kprobe/__x64_sys_dup2 -- detect reverse shell dup2 patterns
// ---------------------------------------------------------------------------

#[kprobe]
pub fn ac_dup2_check(ctx: ProbeContext) -> u32 {
    match try_dup2_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open on BPF read errors
    }
}

fn try_dup2_check(ctx: &ProbeContext) -> Result<u32, i64> {
    // 0. Cgroup scoping: skip non-enforced cgroups.
    if !is_enforced_cgroup() {
        return Ok(0);
    }

    // 1. Read mode from REVERSE_SHELL_MODE array at index 0.
    let mode = match unsafe { REVERSE_SHELL_MODE.get(0) } {
        Some(m) => *m,
        None => return Ok(0),
    };

    // 2. If disabled, bail out.
    if mode == MODE_OFF {
        return Ok(0);
    }

    // 3. Read newfd (arg1, second argument to dup2).
    //    Syscall signature: dup2(oldfd, newfd)
    //    In kprobe context, arg(0) = oldfd, arg(1) = newfd.
    let newfd: u64 = match unsafe { ctx.arg::<u64>(1) } {
        Some(fd) => fd,
        None => return Ok(0),
    };

    // Only care about redirection to stdin (0) or stdout (1).
    if newfd > 1 {
        return Ok(0);
    }

    // 4. Get current process comm.
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    // 5. Check if the process is a known shell/interpreter.
    if !is_known_shell(&comm) {
        return Ok(0);
    }

    // 6. Shell + stdin/stdout redirection detected -- emit event.
    let oldfd: u64 = match unsafe { ctx.arg::<u64>(0) } {
        Some(fd) => fd,
        None => 0,
    };

    if let Some(mut entry) = REVERSE_SHELL_EVENTS.reserve::<ReverseShellEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = 8; // EventType::ReverseShellDetected
            (*ev).verdict = 1; // Verdict::Block
            (*ev).oldfd = oldfd as u32;
            (*ev).newfd = newfd as u32;
            (*ev).comm = comm;
        }
        entry.submit(0);
    }

    // 7. In enforce mode, kill the process.
    if mode == MODE_ENFORCE {
        unsafe {
            bpf_send_signal(9); // SIGKILL
        }
    }

    Ok(0)
}
