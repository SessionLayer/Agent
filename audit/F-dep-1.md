# F-dep-1: rustls TLS 1.2 feature enabled for a TLS-1.3-capable first-party mesh
- Severity: low
- Status: Verified-Fixed
- Area: dependency

Flagged by `security-reviewer` in the Session One red-team pass.

## Issue
`Cargo.toml` opted `rustls` into the `tls12` feature. Both ends of the Agent's
live plane (Agent dials the Gateway) are first-party SessionLayer software, so
TLS 1.3-only is achievable and removes all TLS 1.2 negotiation/downgrade
surface. rustls' TLS 1.2 is AEAD/ECDHE-only (not unsafe today) and nothing
handshakes yet — hence low — but it baked a looser default into the scaffold the
S13 transport would inherit.

## Fix
Removed `"tls12"` from the rustls feature set (`["ring", "std", "logging"]`), so
the fleet is TLS 1.3-only by construction. Rationale recorded in `Cargo.toml`;
re-add only with a documented interop requirement.
