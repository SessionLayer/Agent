//! The verification-identity policy a node trusts (SUPPLY-CHAIN.md §3). Compiled
//! defaults pin the SessionLayer/Agent release workflow; overridable for private
//! Sigstore deployments. Identity is matched *structurally* (prefix/equality) —
//! no regex engine, so there is no ReDoS surface on the boot-critical path.

/// Fulcio X.509v3 extension OIDs (`1.3.6.1.4.1.57264.1.*`).
pub const OID_FULCIO_ISSUER_LEGACY: &str = "1.3.6.1.4.1.57264.1.1";
pub const OID_FULCIO_ISSUER: &str = "1.3.6.1.4.1.57264.1.8";
pub const OID_FULCIO_SOURCE_REPO_URI: &str = "1.3.6.1.4.1.57264.1.12";

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// The OIDC issuer that minted the CI identity token.
    pub oidc_issuer: String,
    /// A SAN identity is accepted iff it starts with this prefix. Pinning through
    /// `…/release.yml@refs/tags/v` binds repo + **workflow file** + tag-ref, so a
    /// signature from any other workflow (or a branch push) is refused.
    pub workflow_ref_prefix: String,
    /// The Fulcio source-repository URI the cert must carry.
    pub source_repo_uri: String,
    /// The SLSA provenance build type.
    pub build_type: String,
    /// Refuse if the pinned trust root pins **no** CT-log key, so a ctlog-less
    /// `trusted_root.json` cannot silently make SCT verification inert (a
    /// rogue-Fulcio-off-log cert would then slip through undetected). On for the
    /// pinned production identity; relaxed for a custom `--expect-*` deployment
    /// that may not run a CT log.
    pub require_certificate_transparency: bool,
}

impl VerificationPolicy {
    /// The pinned production identity for the SessionLayer Agent.
    pub fn sessionlayer_agent() -> Self {
        Self {
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
            workflow_ref_prefix:
                "https://github.com/SessionLayer/Agent/.github/workflows/release.yml@refs/tags/v"
                    .into(),
            source_repo_uri: "https://github.com/SessionLayer/Agent".into(),
            build_type: "https://actions.github.io/buildtypes/workflow/v1".into(),
            require_certificate_transparency: true,
        }
    }

    pub fn san_matches(&self, san: &str) -> bool {
        san.starts_with(&self.workflow_ref_prefix)
    }
}
