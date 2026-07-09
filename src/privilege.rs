//! Non-root runtime posture (FR-CONN-6 / Design §9.3, decision D24).
//!
//! **Why this is a hard requirement, not a nicety.** Node host keys are
//! root-only. If the Agent ran as root, a compromise of the Agent *process*
//! would be enough to read the host key and impersonate the node — collapsing
//! the platform's host-identity guarantee. Running non-root raises the bar from
//! "agent-process-compromise" to "node-root-compromise".
//!
//! The **guarantee** is provided structurally by the container `USER` directive
//! (see `Dockerfile`) and the documented deployment precondition. The function
//! below is a cheap secondary *detector*: if the Agent ever finds itself running
//! as root it logs a loud alarm at ERROR (so it survives the common
//! `warn`-suppressing log filters). It intentionally does not hard-exit — the
//! enforcement point is the immutable image/deployment, and a scaffold that
//! refuses to start would be a poor place to make that policy call. Later
//! sessions MUST promote this to fail-closed once the Agent gains host-key
//! access / credential storage (S12), because from that point a root process can
//! actually read the host key.
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

/// Emit a loud alarm if the Agent is running as root. See the module docs for
/// why this is a violation of a hard deployment precondition (FR-CONN-6).
///
/// Logs at ERROR so the alarm is not swallowed by a `warn`-level log filter —
/// the misconfiguration this guards against often coincides with terse logging.
pub fn warn_if_root() {
    if is_root() {
        tracing::error!(
            requirement = "FR-CONN-6",
            "SessionLayer Agent is running as ROOT (euid=0). This violates a hard \
             deployment precondition: a root agent can read the node host key and \
             impersonate the node. Run as a dedicated non-root user (the container \
             image already does)."
        );
    }
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
