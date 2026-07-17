//! The seccomp allow-list actually ENFORCES: a syscall not on it KILLs the process
//! (`SECCOMP_RET_KILL_PROCESS`), and a syscall on it is permitted. Proves the
//! filter is not silently permissive — load-bearing for the KillProcess-default
//! choice (a missed syscall is fail-deadly, so enforcement must be real).
//!
//! Forks so only the child is sandboxed. The BPF program is compiled in the parent
//! so the forked child does **no heap allocation** before the test syscall
//! (fork-safety: no allocator lock can be held across the fork).
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use sessionlayer_agent::hardening::testing;

/// Run `child` in a forked process and return its wait status.
///
/// SAFETY: the child does only async-signal-safe work (a couple of raw syscalls +
/// `_exit`) with no heap allocation, so a `fork()` in this (near-single-threaded)
/// test process cannot deadlock on an allocator lock held by another thread.
fn in_forked_child(child: impl FnOnce()) -> libc::c_int {
    match unsafe { libc::fork() } {
        -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            child();
            unsafe { libc::_exit(0) }; // reached only if the child was NOT killed
        }
        pid => {
            let mut status: libc::c_int = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(r, pid, "waitpid returned the wrong pid");
            status
        }
    }
}

#[test]
fn a_syscall_off_the_allow_list_kills_the_process() {
    // Compiled in the PARENT so the child allocates nothing before the syscall.
    let program = testing::compile_seccomp().expect("compile the seccomp program");

    let status = in_forked_child(|| {
        if testing::apply_seccomp(&program).is_err() {
            unsafe { libc::_exit(97) }; // install failed — distinct from "not killed"
        }
        // `ptrace` is deliberately NOT on the allow-list → this must be KILLED.
        unsafe {
            libc::syscall(libc::SYS_ptrace, 0i64, 0i64, 0i64, 0i64);
        }
    });

    assert!(
        libc::WIFSIGNALED(status),
        "the child must be KILLED by a signal; instead it exited with code {} \
         (seccomp did not enforce)",
        libc::WEXITSTATUS(status)
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSYS,
        "the kill must be SIGSYS (SECCOMP_RET_KILL_PROCESS), not another signal"
    );
}

#[test]
fn an_allowed_syscall_still_succeeds_under_the_filter() {
    // The mirror image: a syscall ON the allow-list (getpid) must NOT be killed —
    // the filter permits the real workload, it does not blanket-deny.
    let program = testing::compile_seccomp().expect("compile the seccomp program");

    let status = in_forked_child(|| {
        if testing::apply_seccomp(&program).is_err() {
            unsafe { libc::_exit(97) };
        }
        // getpid is on the allow-list; this must return normally → clean exit 0.
        unsafe {
            libc::syscall(libc::SYS_getpid);
        }
    });

    assert!(
        !libc::WIFSIGNALED(status),
        "an allowed syscall must not be killed (got signal {})",
        libc::WTERMSIG(status)
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the child should exit cleanly after an allowed syscall"
    );
}
