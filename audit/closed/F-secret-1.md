# F-secret-1: operator MtlsJoin private key read into a non-zeroizing String
- Severity: low
- Status: Verified-Fixed
- Area: secret

## Summary
`JoinConfig::build()` loaded the MtlsJoin operator PKI private key via
`std::fs::read_to_string(key_file)` into a plain `String` that was never wrapped
in `Zeroizing`. Every other secret in the crate (join token, workload token, the
persisted mTLS key) is a scrub-on-drop `Zeroizing` buffer; the operator PKI key —
the highest-value, longest-lived join secret — was the sole exception, left in a
freed-but-unscrubbed heap allocation.

## Root cause / data flow
`src/config.rs` (Mtls arm): `let key = std::fs::read_to_string(key_file)…` → a
plain `String` holding the private-key PEM, passed by `&key` to
`MtlsJoin::from_pem` and dropped un-scrubbed. Missing control: hold the secret in
a `Zeroizing` buffer like the rest of the codebase.

## Impact
Defense-in-depth memory-hygiene gap (CWE-316): the operator's long-lived private
key lingers in freed heap (core-dump / memory-disclosure exposure). Local only,
not a remote-reachable exploit; the key is already on disk the process can read.

## Remediation (applied)
`src/config.rs`: wrap the read in `Zeroizing::new(std::fs::read_to_string(…)?)`
so the buffer is scrubbed on drop. `MtlsJoin::from_pem` still receives `&str` via
Deref coercion. Gate green.

## Residual note
The `read_secret` token path (`config.rs`) has the same transient-plain-`String`
shape before it re-wraps in `Zeroizing`; the operator key was strictly worse
(never wrapped at all). Left minimal; can be tightened if desired.
