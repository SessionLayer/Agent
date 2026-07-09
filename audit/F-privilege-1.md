# F-privilege-1: root-detector alarm was suppressible by the log filter
- Severity: low
- Status: Verified-Fixed
- Area: privilege

Flagged by `security-reviewer` in the Session One red-team pass.

## Issue
`privilege::warn_if_root()` — the only runtime signal for a root deployment —
emitted at `WARN`. A process started with `--log error` / `RUST_LOG=error`
produced zero output, so a root deployment combined with terse logging (a
common pairing when things are already off-nominal) yielded total silence.

## Fix
The alarm now emits at `tracing::error!`, so it survives the common
`warn`-suppressing filters. Module docs updated. (Enforcement of the non-root
posture remains structural — the immutable container `USER` directive — with
this probe as a secondary detector.)
