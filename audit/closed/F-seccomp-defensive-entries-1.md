# F-seccomp-defensive-entries-1: KILL-default seccomp allow-list drift risk
- Severity: medium
- Status: Verified-Fixed
- Area: hardening

## Context / root cause
`src/hardening/imp.rs` installs the seccomp filter with a
`SeccompAction::KillProcess` default: **any** syscall not on the allow-list is an
instant `SECCOMP_RET_KILL_PROCESS` — fleet-wide, fail-deadly (the S21 FIONREAD /
`F-seccomp-1` class, where a resolver `ioctl` reachable only on hostname lookups
crash-looped the Agent). The allow-list fit the exact syscalls today's
tokio/ring/glibc workload issues, but it omitted several that a routine
glibc/tokio/ring/kernel bump can legitimately reach — and that the Gateway
defensively already carries. A `KillProcess` default turns any such newly-reached
syscall into a crash-loop across the whole fleet at once, so the allow-list should
carry the low-risk, arch-portable defensive entries rather than track the workload
exactly.

## Fix
Added to the **COMMON** allow-list (verified present on both x86_64 and
aarch64-gnu, so no portability cost — kept out of the x86_64-only block):
`openat2`, `close_range` (fd/open path), `mlock`, `mlock2`, `mlockall` (secret-page
locking by `zeroize`/ring), `getgroups`, `getresuid`, `getresgid`
(credential-introspection reads), `sched_setaffinity` (tokio core pinning),
`rt_sigpending`, `rt_sigsuspend` (signal glibc paths). All are read-only or benign
under the Agent's rlimits/non-root/Landlock posture; none widens the reachable
attack surface meaningfully (e.g. `TIOCSTI`-class `ioctl` stays killed, `ptrace`
stays killed).

## Regression
- `src/hardening/imp.rs::tests::allow_list_carries_defensive_syscalls` — asserts
  each new syscall is in `allowed_syscalls()`, so a future removal is caught by CI
  rather than in production.
- `tests/seccomp_kill.rs` (a disallowed syscall is still KILLed) and
  `tests/splice_e2e.rs` (the real dial-back/splice workload runs under the filter)
  continue to prove the filter both enforces and permits the live path.

## Follow-up (out of scope)
A seccomp `Log`/dry-run mode (audit-only run to observe would-be kills before
enforcing `KillProcess`) was suggested to de-risk future allow-list drift
operationally; it is not implemented here — the defensive entries are the fix.
Track for a future hardening pass.
