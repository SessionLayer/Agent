//! Verify-before-update (NFR-7): Sigstore signature + provenance + anti-rollback (fail-closed).

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
    /// A validly-signed but OLDER (or unparseable-version) release — refused so a
    /// signed downgrade to a known-vulnerable build can't be forced.
    #[error("refusing downgrade: candidate {candidate} is not newer than current {current} (pass --allow-downgrade to override)")]
    Downgrade { candidate: String, current: String },
}

pub struct SelfUpdater {
    trust: TrustRoot,
    policy: VerificationPolicy,
    min_version: Option<semver::Version>,
    allow_downgrade: bool,
}

impl SelfUpdater {
    pub fn new(trust: TrustRoot, policy: VerificationPolicy) -> Self {
        Self {
            trust,
            policy,
            min_version: None,
            allow_downgrade: false,
        }
    }

    pub fn from_trust_root_file(path: &Path) -> Result<Self, UpdateError> {
        let bytes = std::fs::read(path).map_err(|source| UpdateError::ReadCandidate {
            path: path.display().to_string(),
            source,
        })?;
        let trust = TrustRoot::from_trusted_root_json(&bytes)?;
        Ok(Self::new(trust, VerificationPolicy::sessionlayer_agent()))
    }

    /// Refuse downgrade unless allow_downgrade is true.
    pub fn with_rollback_floor(
        mut self,
        floor: &str,
        allow_downgrade: bool,
    ) -> Result<Self, UpdateError> {
        self.min_version =
            Some(
                semver::Version::parse(floor).map_err(|e| UpdateError::Downgrade {
                    candidate: "?".into(),
                    current: format!("{floor} (unparseable: {e})"),
                })?,
            );
        self.allow_downgrade = allow_downgrade;
        Ok(self)
    }

    pub fn verify(
        &self,
        binary: &[u8],
        blob: &Bundle,
        provenance: &Bundle,
    ) -> Result<VerifiedRelease, VerifyError> {
        supply_chain::verify_binary(binary, blob, provenance, &self.policy, &self.trust)
    }

    fn check_rollback(&self, verified: &VerifiedRelease) -> Result<(), UpdateError> {
        let Some(min) = &self.min_version else {
            return Ok(());
        };
        if self.allow_downgrade {
            return Ok(());
        }
        let current = min.to_string();
        let raw = verified.version.as_deref().unwrap_or("");
        match semver::Version::parse(raw) {
            Ok(cand) if &cand >= min => Ok(()),
            _ => Err(UpdateError::Downgrade {
                candidate: if raw.is_empty() {
                    "<none>".into()
                } else {
                    raw.into()
                },
                current,
            }),
        }
    }

    /// Verify candidate then atomically install (no TOCTOU: verified bytes only).
    pub fn install(
        &self,
        candidate: &Path,
        blob: &Bundle,
        provenance: &Bundle,
        install_to: &Path,
    ) -> Result<VerifiedRelease, UpdateError> {
        let bytes = read_candidate(candidate)?;
        let verified = self.verify(&bytes, blob, provenance)?;
        self.check_rollback(&verified)?;
        atomic_write(&bytes, install_to).map_err(|source| UpdateError::Install {
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

/// Write verified bytes to temp, make executable, rename to install_to (atomic).
fn atomic_write(bytes: &[u8], install_to: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = install_to
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = install_to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".into());
    let tmp: PathBuf = dir.join(format!(".{name}.{}.new", std::process::id()));

    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_EXCL: never reuse an attacker-planted temp
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o755);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, install_to)
    };
    write().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}
