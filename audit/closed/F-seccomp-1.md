# F-seccomp-1: `ioctl(FIONREAD)` missing from the seccomp allow-list — Agent dies on first hostname DNS
- Severity: high
- Status: Verified-Fixed
- Area: hardening

## Summary
The Session-21 KILL-default seccomp allow-list omitted `ioctl`. glibc `getaddrinfo`
issues `ioctl(fd, FIONREAD)` before each `recvfrom` on a UDP DNS answer, so on every
**hostname** resolution the Agent hit a disallowed syscall and was
`SECCOMP_RET_KILL_PROCESS`-killed (SIGSYS) on its **first DNS lookup**. The real
DaemonSet (`--cp-endpoint https://controlplane.sessionlayer.svc:9443`,
`--gateway-endpoint wss://gw-a.sessionlayer:8443`) would have been **dead on
arrival**. All tests used `127.0.0.1` literals, which skip `getaddrinfo` entirely —
so CI was green while the binary was broken for the production (hostname) path.
Fail-deadly under KILL-default. Found by the kernel-ebpf T3 review.

## Fix (`src/hardening/imp.rs`, `compile_seccomp`)
Add `ioctl` to the **shared common** allow-list (both x86_64 + aarch64),
**arg-restricted** via a `SeccompRule` + `SeccompCondition` on arg 1 (the request):
only `FIONREAD` and `FIONBIO` are allowed; every other ioctl request (e.g.
`TIOCSTI` input injection, `TIOCGWINSZ`) is still killed. This keeps the syscall
surface tight rather than blanket-allowing ioctl.

## Regression guards (must FAIL before the fix, PASS after)
- `tests/seccomp_kill.rs::ioctl_is_arg_restricted_to_the_resolver_requests` —
  under the real production filter, `ioctl(FIONREAD)` survives and a non-resolver
  ioctl is SIGSYS-killed (deterministic; proves both the allow and the tight surface).
- `tests/seccomp_kill.rs::glibc_hostname_resolution_survives_the_filter` — a real
  `getaddrinfo` on a hostname under the filter is not self-killed (the real path).
- `tests/hardening_e2e.rs` (F2) — now asserts the Agent is **not signal-killed** +
  a post-filter survival marker, so an incomplete allow-list on the startup path
  can no longer masquerade as a clean non-zero exit (this is why F1 slipped).

## Related (same review, addressed together)
- Egress: permit TCP:53 when any endpoint is a hostname (TCP-DNS fallback, F4);
  Landlock RO on the join-material parent dir to survive token rotation (F5).
- Honesty/doctrine: soften the port-scoped egress prose, ship the load-bearing
  egress NetworkPolicy, add `--require-full-landlock`, document UDP/host-scope/<6.7
  gaps (F6, redteam LOW) — see `audit/F-hardening-1.md`.
- aarch64 allow-list is CI-unproven (x86_64 only) — documented (F7).
