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
fn ioctl_is_arg_restricted_to_the_resolver_requests() {
    // Regression guard for F1 (the fail-deadly getaddrinfo footgun): the filter must
    // allow `ioctl(fd, FIONREAD)` (glibc's UDP-DNS receive path needs it) but KILL
    // any other ioctl request — proving the fix is arg-restricted, not blanket. This
    // FAILS before F1 (ioctl absent → FIONREAD killed) and PASSES after.
    let program = testing::compile_seccomp().expect("compile the seccomp program");

    let allowed = in_forked_child(|| {
        if testing::apply_seccomp(&program).is_err() {
            unsafe { libc::_exit(97) };
        }
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let mut avail: libc::c_int = 0;
        unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd as libc::c_long,
                libc::FIONREAD as libc::c_long,
                &mut avail as *mut libc::c_int as libc::c_long,
            );
        }
    });
    assert!(
        !libc::WIFSIGNALED(allowed),
        "ioctl(FIONREAD) must be allowed — glibc getaddrinfo needs it; child killed by {}",
        libc::WTERMSIG(allowed)
    );

    let denied = in_forked_child(|| {
        if testing::apply_seccomp(&program).is_err() {
            unsafe { libc::_exit(97) };
        }
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        // TIOCGWINSZ is a benign ioctl that is NOT on the resolver allow-list.
        unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd as libc::c_long,
                libc::TIOCGWINSZ as libc::c_long,
                0i64,
            );
        }
    });
    assert!(
        libc::WIFSIGNALED(denied) && libc::WTERMSIG(denied) == libc::SIGSYS,
        "a non-resolver ioctl must be KILLed by SIGSYS — the arg-restriction must be real"
    );
}

#[test]
fn glibc_hostname_resolution_survives_the_filter() {
    // The real-path guard the numeric-loopback E2E could never give: resolving a
    // HOSTNAME under the production filter must NOT self-KILL (127.0.0.1 literals
    // skip getaddrinfo, which is exactly how F1 hid). The only failure mode here is a
    // seccomp SIGSYS — a network/DNS failure returns an error, not a kill, so there
    // is no false failure where DNS is unavailable.
    use std::net::ToSocketAddrs;
    // Pre-warm NSS + the allocator in the parent so the forked child reuses loaded
    // libraries (fork-safety: minimise child heap churn).
    let _ = ("example.com", 443u16).to_socket_addrs();

    let program = testing::compile_seccomp().expect("compile the seccomp program");
    let status = in_forked_child(|| {
        if testing::apply_seccomp(&program).is_err() {
            unsafe { libc::_exit(97) };
        }
        let _ = ("example.com", 443u16).to_socket_addrs();
    });
    assert!(
        !libc::WIFSIGNALED(status),
        "hostname resolution under the filter was KILLED by signal {} — a resolver \
         syscall (e.g. ioctl FIONREAD) is missing from the allow-list",
        libc::WTERMSIG(status)
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
