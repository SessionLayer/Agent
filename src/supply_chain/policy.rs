pub const OID_FULCIO_ISSUER_LEGACY: &str = "1.3.6.1.4.1.57264.1.1";
pub const OID_FULCIO_ISSUER: &str = "1.3.6.1.4.1.57264.1.8";
pub const OID_FULCIO_SOURCE_REPO_URI: &str = "1.3.6.1.4.1.57264.1.12";

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub oidc_issuer: String,
    pub workflow_ref_prefix: String,
    pub source_repo_uri: String,
    pub build_type: String,
    pub require_certificate_transparency: bool,
}

impl VerificationPolicy {
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
