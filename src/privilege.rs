//! Non-root runtime posture (FR-CONN-6 / Design §9.3, decision D24).
//!
//! **Why this is a hard requirement, not a nicety.** Node host keys are
//! root-only. If the Agent ran as root, a compromise of the Agent *process*
//! would be enough to read the host key and impersonate the node — collapsing
//! the platform's host-identity guarantee. Running non-root raises the bar from
//! "agent-process-compromise" to "node-root-compromise".
//!
//! The **guarantee** is provided structurally by the container `USER` directive
//! (see `Dockerfile`) and the documented deployment precondition. On top of that
//! the Agent now performs a **fail-closed** runtime check at startup
//! ([`require_non_root`]): from Session Twelve the Agent stores a renewable mTLS
//! credential and is one hop from node-host-key access, so a root Agent is a live
//! hazard, not a hypothetical — it refuses to start (resolving the Session-One
//! carry-forward F-privilege-3, which asked to promote the earlier warn-only
//! probe once credentials landed).
//!
//! **Scope of the check:** this probe detects only effective-UID 0. It does
//! **not** attest capability posture — a non-root process granted
//! `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` (e.g. via a Kubernetes
//! `securityContext.capabilities.add`) could still read the host key while
//! `euid != 0`. Capability hygiene is enforced at the deployment layer
//! (`runAsNonRoot`, drop all capabilities); a future fail-closed promotion may
//! additionally inspect `/proc/self/status` `CapEff`.

/// The effective UID of the current process, or `None` on non-Unix targets
/// where the concept does not apply.
#[cfg(unix)]
pub fn effective_uid() -> Option<u32> {
    // SAFETY: `geteuid(2)` is always successful, takes no arguments, and has no
    // side effects; it cannot fail and never touches memory we pass in.
    Some(unsafe { libc::geteuid() })
}

/// The effective UID of the current process, or `None` on non-Unix targets.
#[cfg(not(unix))]
pub fn effective_uid() -> Option<u32> {
    None
}

/// Whether the process is running as root (effective UID 0). Always `false`
/// where the notion does not apply.
pub fn is_root() -> bool {
    matches!(effective_uid(), Some(0))
}

/// Raised when the Agent is started as root — a hard, fail-closed refusal.
#[derive(Debug, thiserror::Error)]
#[error(
    "SessionLayer Agent must not run as root (euid=0): a root agent can read the node host key and \
     impersonate the node (FR-CONN-6 / Design §9.3). Run as a dedicated non-root user."
)]
pub struct RunningAsRoot;

/// Fail closed if the Agent is running as root (effective UID 0).
///
/// This is the runtime enforcement point (FR-CONN-6): from S12 the Agent holds a
/// renewable credential and is adjacent to host-key access, so a root process is
/// a real hazard. Returns `Err(RunningAsRoot)` on euid 0 so the caller aborts
/// before any credential is loaded or issued; the loud ERROR log survives a
/// `warn`-suppressing filter (the misconfiguration often coincides with terse
/// logging).
pub fn require_non_root() -> Result<(), RunningAsRoot> {
    if is_root() {
        tracing::error!(
            requirement = "FR-CONN-6",
            "SessionLayer Agent is running as ROOT (euid=0) — refusing to start. A root agent can \
             read the node host key and impersonate the node. Run as a dedicated non-root user \
             (the container image already does)."
        );
        return Err(RunningAsRoot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_root_agrees_with_effective_uid() {
        // Do not assert a specific UID (CI may or may not run as root); only
        // that the two accessors are internally consistent.
        assert_eq!(is_root(), matches!(effective_uid(), Some(0)));
    }

    #[cfg(unix)]
    #[test]
    fn effective_uid_is_available_on_unix() {
        assert!(effective_uid().is_some());
    }
}
