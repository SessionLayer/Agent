//! Linux implementation of Tier-0 hardening (seccomp + Landlock + coredump).
//!
//! Applied in this order: coredump/ptrace hygiene → Landlock (fs + net egress) →
//! seccomp **last**, so the Landlock syscalls run before the seccomp filter is
//! active and never need a slot on the allow-list.

use std::collections::BTreeMap;

use anyhow::Context;

use super::{HardeningPlan, Landlock, Report};

/// Read-only system paths the runtime + glibc resolver legitimately need: shared
/// libraries (incl. lazily-`dlopen`ed NSS modules), `/etc` (resolv.conf, nsswitch,
/// hosts), and the process/dev pseudo-filesystems. Writes stay confined to the
/// data-dir; this only widens *reads*, which on the Agent's read-only rootfs expose
/// nothing sensitive (the node's host keys live outside the Agent's container).
/// Non-existent entries are skipped so the same list works on distroless and Debian.
const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev", "/run",
];

pub fn apply(plan: &HardeningPlan) -> anyhow::Result<Report> {
    disable_coredumps().context("disabling coredumps")?;
    let landlock = apply_landlock(plan).context("applying the Landlock ruleset")?;
    match landlock {
        Landlock::Unavailable => tracing::warn!(
            "Landlock is UNAVAILABLE on this kernel — running with an ACCEPTED-RISK degrade \
             (seccomp + loopback-only splice validation still hold). Deploy on a Landlock-capable \
             kernel (Linux ≥5.13; network egress needs ≥6.7) for full Tier-0 filesystem/egress \
             confinement."
        ),
        Landlock::PartiallyEnforced => tracing::warn!(
            "Landlock is PARTIALLY enforced — some access types are unsupported on this kernel \
             (network egress confinement needs ABI v4 / Linux ≥6.7). Documented degrade."
        ),
        Landlock::FullyEnforced => {}
    }
    // Seccomp LAST: everything above (incl. Landlock syscalls) has already run.
    let seccomp_syscalls = install_seccomp().context("installing the seccomp filter")?;

    let report = Report {
        coredumps_disabled: true,
        landlock,
        seccomp_syscalls,
        allowed_ports: plan.allowed_connect_ports.clone(),
    };
    tracing::info!(
        landlock = ?report.landlock,
        seccomp_syscalls = report.seccomp_syscalls,
        coredumps_disabled = report.coredumps_disabled,
        "Tier-0 runtime hardening applied"
    );
    Ok(report)
}

/// `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`: no coredump can capture the mTLS key /
/// join token, and the process cannot be `ptrace`d for its memory. Fail closed.
fn disable_coredumps() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads a valid `rlimit` for a valid resource id; no aliasing.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
        return Err(anyhow::anyhow!(
            "setrlimit(RLIMIT_CORE, 0): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` passes only integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(anyhow::anyhow!(
            "prctl(PR_SET_DUMPABLE, 0): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn apply_landlock(plan: &HardeningPlan) -> anyhow::Result<Landlock> {
    use landlock::{
        Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // ABI v4 is the first with network (ConnectTcp) support; BestEffort downgrades
    // gracefully (and loudly, via the returned status) on older kernels.
    let abi = ABI::V4;
    let rw = AccessFs::from_all(abi);
    let ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::ConnectTcp)?
        .create()?;

    // Writable: the credential data-dir (must exist — fail closed if not).
    for p in &plan.read_write_paths {
        let fd = PathFd::new(p).with_context(|| format!("data-dir {p:?} must exist"))?;
        ruleset = ruleset.add_rule(PathBeneath::new(fd, rw))?;
    }
    // Read-only: bootstrap CA + join files. Grant the containing DIRECTORY (not the
    // file) so a kubelet projected-token / configmap rotation — which atomically
    // swaps the file's inode via a new `..data` dir + symlink flip — stays readable
    // at a later re-enroll (F5: an inode-scoped file rule would deny the rotated
    // token). An inline token has no file → skipped.
    for p in &plan.read_only_paths {
        let target = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(p);
        if let Ok(fd) = PathFd::new(target) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, ro))?;
        }
    }
    // Read-only: the system paths the runtime/resolver need (skip missing).
    for p in SYSTEM_READ_PATHS {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, ro))?;
        }
    }
    // Egress: TCP connect is allowed only to these destination ports (CP, each
    // Gateway, the loopback splice, and the OTLP collector when configured).
    for port in &plan.allowed_connect_ports {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    let status = ruleset.restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => Landlock::FullyEnforced,
        RulesetStatus::PartiallyEnforced => Landlock::PartiallyEnforced,
        RulesetStatus::NotEnforced => Landlock::Unavailable,
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn install_seccomp() -> anyhow::Result<usize> {
    let (program, count) = compile_seccomp()?;
    apply_seccomp(&program)?;
    Ok(count)
}

/// Compile the production seccomp program (allow-list → BPF). Split from
/// [`apply_seccomp`] so a fork-based test can build it in the parent (this
/// allocates) and install it in the child (no allocation → fork-safe).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn compile_seccomp() -> anyhow::Result<(seccompiler::BpfProgram, usize)> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };

    let syscalls = allowed_syscalls();
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for sc in &syscalls {
        // An empty rule set means "match unconditionally" → the match action (Allow).
        rules.insert(*sc, vec![]);
    }

    // `ioctl` is arg-restricted, NOT blanket-allowed: glibc `getaddrinfo` issues
    // `ioctl(fd, FIONREAD)` before each `recvfrom` on a UDP DNS answer, so a missing
    // ioctl would SIGSYS-kill the Agent on its first *hostname* lookup (the numeric
    // loopback tests skip getaddrinfo, which is how this hid). Allow only the
    // resolver's `FIONREAD`/`FIONBIO` request codes; every other ioctl (e.g.
    // `TIOCSTI` input injection) stays killed.
    // c_ulong == u64 on the LP64 targets, so no cast (clippy: same-type).
    let ioctl_rules = [libc::FIONREAD, libc::FIONBIO]
        .into_iter()
        .map(|req| {
            SeccompRule::new(vec![SeccompCondition::new(
                1, // ioctl(fd, request, ...): the request is arg 1
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::Eq,
                req,
            )?])
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_ioctl, ioctl_rules);

    let syscall_count = rules.len();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess, // any syscall off the allow-list kills the process
        SeccompAction::Allow,
        target_arch(),
    )?;
    let bpf: BpfProgram = filter.try_into()?;
    Ok((bpf, syscall_count))
}

/// Install a compiled seccomp program on every thread of the process (TSYNC).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn apply_seccomp(program: &seccompiler::BpfProgram) -> anyhow::Result<()> {
    seccompiler::apply_filter_all_threads(program).map_err(anyhow::Error::from)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_seccomp() -> anyhow::Result<usize> {
    // The allow-list is enumerated per-arch; only the two shipped targets are
    // defined. Fail closed rather than run unhardened on an unsupported arch.
    anyhow::bail!("the seccomp allow-list is only defined for x86_64 and aarch64")
}

#[cfg(target_arch = "x86_64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::x86_64
}

#[cfg(target_arch = "aarch64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::aarch64
}

/// The syscall allow-list for the Agent's real workload: the tokio runtime, the
/// pinned rustls/ring TLS stack, tonic/hyper gRPC (enroll/renew), the
/// mutually-authenticated WebSocket control channel + dial-back, the loopback
/// splice, single-writer file I/O in the data-dir, and glibc name resolution.
/// Anything outside it is killed (`SECCOMP_RET_KILL_PROCESS`).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn allowed_syscalls() -> Vec<i64> {
    // Present on both x86_64 and aarch64.
    let mut s: Vec<i64> = vec![
        // ---- file & directory I/O (data-dir persist, config reads, NSS dlopen) ----
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_openat,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_ftruncate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_getcwd,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        // ---- async I/O readiness (tokio/mio epoll + eventfd waker + timers) ----
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_eventfd2,
        libc::SYS_ppoll,
        // ---- networking (CP mTLS, Gateway WSS, dial-back, loopback splice, DNS) ----
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        // ---- memory ----
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        // ---- threads & synchronisation (tokio workers, pthread) ----
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_futex_waitv,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_set_tid_address,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_yield,
        libc::SYS_membarrier,
        // ---- signals (tokio SIGTERM/SIGINT, panic=abort path) ----
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        // ---- time ----
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        // ---- misc process/runtime introspection ----
        libc::SYS_getrandom,
        libc::SYS_prlimit64,
        // tokio/std name their worker threads → `pthread_setname_np` on self →
        // prctl(PR_SET_NAME); without it every worker would SIGSYS at startup.
        libc::SYS_prctl,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
    ];

    // x86_64 keeps the legacy (non-`*at`) forms + TLS setup via arch_prctl.
    #[cfg(target_arch = "x86_64")]
    s.extend_from_slice(&[
        libc::SYS_arch_prctl,
        libc::SYS_open,
        libc::SYS_poll,
        libc::SYS_epoll_wait,
        libc::SYS_pipe,
        libc::SYS_dup2,
        libc::SYS_access,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_readlink,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_chmod,
    ]);

    s
}
