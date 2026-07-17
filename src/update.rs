//! Verify-before-run/update (NFR-7, the runtime control). The Agent will only
//! run or install to a binary whose Sigstore signature + provenance + identity
//! verify against the pinned release identity. Both entry points **verify first
//! and fail closed**: [`SelfUpdater::run`] launches a candidate only after it
//! verifies; [`SelfUpdater::install`] never writes an unverified candidate into
//! place. The launch step is injected so the boundary is directly testable.

use std::path::{Path, PathBuf};

use crate::supply_chain::{
    self, Bundle, TrustRoot, VerificationPolicy, VerifiedRelease, VerifyError,
};

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("reading candidate {path}: {source}")]
    ReadCandidate {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("installing verified binary to {path}: {source}")]
    Install {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("launching verified binary: {0}")]
    Launch(#[source] std::io::Error),
}

/// How a verified binary is executed. Abstracted so the "never launch an
/// unverified binary" boundary can be asserted without exec-ing in tests.
pub trait Launcher {
    /// Launch `binary`. The real impl `execv`s and so only returns on failure.
    fn launch(&self, binary: &Path) -> std::io::Result<()>;
}

/// Production launcher: replace this process image with the verified binary.
pub struct ExecLauncher {
    pub args: Vec<std::ffi::OsString>,
}

impl Launcher for ExecLauncher {
    #[cfg(unix)]
    fn launch(&self, binary: &Path) -> std::io::Result<()> {
        use std::os::unix::process::CommandExt;
        // `exec` only returns if it FAILED; on success the image is replaced.
        Err(std::process::Command::new(binary).args(&self.args).exec())
    }
    #[cfg(not(unix))]
    fn launch(&self, binary: &Path) -> std::io::Result<()> {
        let status = std::process::Command::new(binary)
            .args(&self.args)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

pub struct SelfUpdater {
    trust: TrustRoot,
    policy: VerificationPolicy,
}

impl SelfUpdater {
    pub fn new(trust: TrustRoot, policy: VerificationPolicy) -> Self {
        Self { trust, policy }
    }

    /// Load the pinned Sigstore trust root from an operator-supplied
    /// `trusted_root.json`, with the production SessionLayer/Agent identity.
    pub fn from_trust_root_file(path: &Path) -> Result<Self, UpdateError> {
        let bytes = std::fs::read(path).map_err(|source| UpdateError::ReadCandidate {
            path: path.display().to_string(),
            source,
        })?;
        let trust = TrustRoot::from_trusted_root_json(&bytes)?;
        Ok(Self::new(trust, VerificationPolicy::sessionlayer_agent()))
    }

    pub fn verify(
        &self,
        binary: &[u8],
        blob: &Bundle,
        provenance: &Bundle,
    ) -> Result<VerifiedRelease, VerifyError> {
        supply_chain::verify_binary(binary, blob, provenance, &self.policy, &self.trust)
    }

    /// Verify `candidate` and, only on success, launch it (fail closed).
    pub fn run<L: Launcher>(
        &self,
        candidate: &Path,
        blob: &Bundle,
        provenance: &Bundle,
        launcher: &L,
    ) -> Result<VerifiedRelease, UpdateError> {
        let bytes = read_candidate(candidate)?;
        let verified = self.verify(&bytes, blob, provenance)?;
        tracing::info!(digest = %verified.digest_hex, "candidate verified — launching");
        launcher.launch(candidate).map_err(UpdateError::Launch)?;
        Ok(verified)
    }

    /// Verify `candidate` and, only on success, atomically install it to
    /// `install_to`. An unverified candidate is **never** written into place.
    pub fn install(
        &self,
        candidate: &Path,
        blob: &Bundle,
        provenance: &Bundle,
        install_to: &Path,
    ) -> Result<VerifiedRelease, UpdateError> {
        let bytes = read_candidate(candidate)?;
        let verified = self.verify(&bytes, blob, provenance)?;
        atomic_replace(candidate, install_to).map_err(|source| UpdateError::Install {
            path: install_to.display().to_string(),
            source,
        })?;
        tracing::info!(digest = %verified.digest_hex, to = %install_to.display(), "verified binary installed");
        Ok(verified)
    }
}

fn read_candidate(path: &Path) -> Result<Vec<u8>, UpdateError> {
    std::fs::read(path).map_err(|source| UpdateError::ReadCandidate {
        path: path.display().to_string(),
        source,
    })
}

/// Copy `candidate` into a temp file in the destination directory, make it
/// executable, then rename over `install_to` (atomic on the same filesystem).
fn atomic_replace(candidate: &Path, install_to: &Path) -> std::io::Result<()> {
    let dir = install_to.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let name = install_to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".into());
    let tmp: PathBuf = dir.join(format!(".{name}.{}.new", std::process::id()));

    std::fs::copy(candidate, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    match std::fs::rename(&tmp, install_to) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}
