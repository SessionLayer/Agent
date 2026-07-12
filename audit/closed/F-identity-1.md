# F-identity-1: CP-supplied gRPC message leaks to startup stderr via the anyhow source chain
- Severity: medium
- Status: Verified-Fixed
- Area: identity

## Summary
`IdentityError::Rpc(#[from] tonic::Status)` renders only the gRPC *code* in its
own `Display` (never the untrusted CP-supplied message). That guard was defeated
on the enroll / startup-renew failure paths in `main.rs`, which wrapped the error
with anyhow's `.context(_)`. thiserror makes the `#[from]` field the error
`source()`, and `.context(_)` preserves the source chain, so
`IdentityError::Rpc.source() == tonic::Status`. `fn main() -> anyhow::Result<()>`
prints a returned `Err` via `Termination` as `{:?}`, and anyhow's Debug walks the
`source()` chain printing each link's `Display`; `tonic::Status`'s `Display`
(`", message: {:?}"`) emits the CP-supplied message → it reaches startup stderr.

This is the exact control the reviewed Session-Four Gateway shipped deliberately
(`gateway/src/main.rs` flattening `anyhow!("… {e}")` wrap + a source-chain
regression test); the S12 port dropped it, using `.context(_)`.

## Root cause / data flow
source: hostile CP `Status` message (untrusted wire text) → `IdentityError::Rpc`
(Display code-only, but `tonic::Status` retained as `source()`) →
`.context("agent enrollment")` / `Err(e).context("startup renewal")` (anyhow
preserves the source) → `fn main` Termination `{:?}` (anyhow Debug walks
`source()`) → sink: startup stderr / log capture. Missing control: the
source-severing boundary wrap.

## Proof of concept (confirmed, local)
Replicating the `main` path:
`Err(IdentityError::Rpc(Status::permission_denied("SECRETCANARY_evil\n\x1b[2Jinjected")))
.context("agent enrollment")` then `format!("{err:?}")` printed:
```
agent enrollment
Caused by:
    0: Control Plane refused the identity RPC (gRPC status PermissionDenied)
    1: code: '…', message: "SECRETCANARY_evil\n\u{1b}[2Jinjected"
```
Reachable only on the pre-loop paths (initial enrollment failure; startup-renew
terminal failure) that propagate to `main`. The renew-ahead loop logs via `%e`
(Display, code-only) and is unaffected.

Mitigating factor bounding the severity: tonic renders the message with `{:?}`,
which escapes raw control bytes (`\n`→`\n`, ESC→`\u{1b}`), so raw
terminal-escape / newline injection is neutralized — the residual is disclosure
of untrusted CP wire text into stderr/logs plus a broken documented invariant.

## Impact
Info disclosure / log poisoning of attacker-influenced (hostile-CP) text on the
Agent's startup stderr, contradicting the module's documented invariant ("never
the CP-supplied message") and regressing the reviewed Gateway baseline.

## Remediation (applied)
`src/main.rs`: both sinks flattened to `.map_err(|e| anyhow::anyhow!("… failed:
{e}"))?` / `Err(anyhow::anyhow!("startup renewal failed: {e}"))`, which formats
only the code-only `Display` and carries no `tonic::Status` source. Regression:
`src/identity.rs::rpc_error_does_not_leak_cp_message` extended with the Gateway's
part-(b) assertion — `anyhow!("… {err}")` yields `chain().count() == 1` and no
canary. Gate green (fmt/clippy/43 tests/audit/deny).
