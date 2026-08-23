#[cfg(unix)]
pub fn effective_uid() -> Option<u32> {
    Some(unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
pub fn effective_uid() -> Option<u32> {
    None
}

pub fn is_root() -> bool {
    matches!(effective_uid(), Some(0))
}

#[derive(Debug, thiserror::Error)]
#[error(
    "SessionLayer Agent must not run as root (euid=0): a root agent can read the node host key and \
     impersonate the node. Run as a dedicated non-root user."
)]
pub struct RunningAsRoot;

pub fn require_non_root() -> Result<(), RunningAsRoot> {
    if is_root() {
        tracing::error!(
            "SessionLayer Agent is running as ROOT (euid=0) - refusing to start. A root agent can \
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
        assert_eq!(is_root(), matches!(effective_uid(), Some(0)));
    }

    #[cfg(unix)]
    #[test]
    fn effective_uid_is_available_on_unix() {
        assert!(effective_uid().is_some());
    }
}
