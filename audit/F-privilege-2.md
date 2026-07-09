# F-privilege-2: euid==0 is an incomplete proxy for "can read the host key"
- Severity: low
- Status: Verified-Fixed
- Area: privilege

Flagged by `security-reviewer` in the Session One red-team pass.

## Issue
The stated threat is a process that can read the root-only node host key, but
`is_root()` only tests effective-UID 0. A non-root process granted
`CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH` (e.g. Kubernetes
`securityContext.capabilities.add`) satisfies the threat while `euid != 0`, so
the detector could report "OK" and give false assurance. The actual control
(distroless `USER 65532` + `runAsNonRoot` + drop-all-capabilities) does cover
this; the gap was that the detector's check is narrower than the property it
guards.

## Fix
`src/privilege.rs` module docs now explicitly state the probe detects only
uid-0 and does not attest capability posture, note that capability hygiene is a
deployment-layer control, and record that the future fail-closed promotion (S12)
may additionally inspect `/proc/self/status` `CapEff`. A one-line doc caveat is
sufficient for the scaffold; no false-assurance claim remains in the code.
