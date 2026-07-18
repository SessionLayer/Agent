//! The pinned trust root: Sigstore Fulcio CA certificates (chain anchor) and
//! Rekor transparency-log public keys. In production these come from a
//! Sigstore-distributed `trusted_root.json` (TUF repo `tuf-repo-cdn.sigstore.dev`),
//! pinned by digest by the operator. Nothing here reaches the network — the file
//! is provided at rest, so verification is fully offline and deterministic.

use base64::Engine as _;
use p256::pkcs8::spki::DecodePublicKey;
use serde::Deserialize;

use super::error::VerifyError;

/// A Sigstore `TimeRange`, in Unix seconds. `end` absent means "still valid, no
/// upper bound". Bounds are **inclusive** of the endpoints (protobuf-specs).
#[derive(Clone, Copy, Debug)]
pub struct TimeRange {
    pub start: i64,
    pub end: Option<i64>,
}

impl TimeRange {
    /// Whether `t` (a trusted log-integration time) falls inside this window.
    pub fn contains(&self, t: i64) -> bool {
        self.start <= t && self.end.is_none_or(|e| t <= e)
    }
}

/// A pinned Fulcio CA certificate carrying the `validFor` window its Sigstore
/// `CertificateAuthority` was trusted for.
#[derive(Clone)]
pub struct FulcioCa {
    pub der: Vec<u8>,
    pub valid_for: TimeRange,
}

/// A pinned Rekor log key carrying the `validFor` window it was trusted for — a
/// bare P-256 key has no X.509 validity of its own, so this window is the only
/// bound that stops a retired-then-compromised log key forging a fresh SET.
#[derive(Clone)]
pub struct RekorKey {
    pub key: p256::ecdsa::VerifyingKey,
    pub valid_for: TimeRange,
}

#[derive(Clone)]
pub struct TrustRoot {
    /// Fulcio CA certificates (root + intermediate), DER, each with its window.
    pub fulcio_cas: Vec<FulcioCa>,
    /// Rekor log signing keys (P-256), each with its window.
    pub rekor_keys: Vec<RekorKey>,
}

impl TrustRoot {
    pub fn from_trusted_root_json(bytes: &[u8]) -> Result<Self, VerifyError> {
        let tr: TrustedRoot = serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::TrustAnchor(format!("trusted_root.json: {e}")))?;

        // A CA's `validFor` bounds every cert in its chain; a malformed/absent
        // window is a malformed trust anchor (fail closed, as the cert bytes are).
        let mut fulcio_cas = Vec::new();
        for ca in &tr.certificate_authorities {
            let valid_for = parse_time_range(ca.valid_for.as_ref())?;
            for cert in &ca.cert_chain.certificates {
                fulcio_cas.push(FulcioCa {
                    der: decode_b64(&cert.raw_bytes)?,
                    valid_for,
                });
            }
        }
        if fulcio_cas.is_empty() {
            return Err(VerifyError::TrustAnchor(
                "trusted_root.json has no Fulcio certificate authorities".into(),
            ));
        }

        // A tlog key we can't fully validate (a future ed25519/RSA log key, Rekor
        // v2, or one with an unparseable `validFor`) is skipped, not fatal — we
        // only need the P-256 keys we can verify AND bound. Failing the whole load
        // on the first odd key would brick verification.
        let mut rekor_keys = Vec::new();
        for tlog in &tr.tlogs {
            let parsed = decode_b64(&tlog.public_key.raw_bytes)
                .and_then(|d| verifying_key_from_spki(&d))
                .ok()
                .zip(parse_time_range(tlog.public_key.valid_for.as_ref()).ok());
            if let Some((key, valid_for)) = parsed {
                rekor_keys.push(RekorKey { key, valid_for });
            }
        }
        if rekor_keys.is_empty() {
            return Err(VerifyError::TrustAnchor(
                "trusted_root.json has no usable P-256 Rekor tlog keys".into(),
            ));
        }

        Ok(Self {
            fulcio_cas,
            rekor_keys,
        })
    }
}

pub(super) fn verifying_key_from_spki(
    der: &[u8],
) -> Result<p256::ecdsa::VerifyingKey, VerifyError> {
    p256::ecdsa::VerifyingKey::from_public_key_der(der)
        .map_err(|e| VerifyError::TrustAnchor(format!("Rekor public key (SPKI DER): {e}")))
}

fn parse_time_range(r: Option<&RawTimeRange>) -> Result<TimeRange, VerifyError> {
    let r = r.ok_or_else(|| {
        VerifyError::TrustAnchor("trusted_root.json entry has no validFor window".into())
    })?;
    Ok(TimeRange {
        start: parse_rfc3339_secs(&r.start)?,
        end: r.end.as_deref().map(parse_rfc3339_secs).transpose()?,
    })
}

/// Parse an RFC3339 timestamp to Unix seconds (fractional seconds floored). The
/// `validFor` bounds are compared against the Rekor `integratedTime`, itself Unix
/// seconds, so sub-second precision is unnecessary — and a hand-rolled parse
/// avoids adding a time crate to the verifier's dependency surface (NFR-7).
fn parse_rfc3339_secs(s: &str) -> Result<i64, VerifyError> {
    let bad = || VerifyError::TrustAnchor(format!("validFor timestamp not RFC3339: {s:?}"));
    let b = s.as_bytes();
    // Fixed 19-char prefix "YYYY-MM-DDThh:mm:ss" (date-time separator T/t/space).
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return Err(bad());
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return Err(bad());
    }
    let num = |a: usize, z: usize| {
        s.get(a..z)
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(bad)
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return Err(bad());
    }

    // Optional fractional seconds, then a mandatory zone (Z or ±hh:mm).
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == frac_start {
            return Err(bad());
        }
    }
    let offset = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1, i + 3)?, num(i + 4, i + 6)?);
            if oh > 23 || om > 59 {
                return Err(bad());
            }
            let mag = oh * 3600 + om * 60;
            if *sign == b'+' {
                mag
            } else {
                -mag
            }
        }
        _ => return Err(bad()),
    };

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3600 + min * 60 + sec - offset)
}

/// Days between 1970-01-01 and the given proleptic-Gregorian date (Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn decode_b64(s: &str) -> Result<Vec<u8>, VerifyError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| VerifyError::TrustAnchor(format!("base64: {e}")))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRoot {
    #[serde(default)]
    tlogs: Vec<Tlog>,
    #[serde(default)]
    certificate_authorities: Vec<CertificateAuthority>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tlog {
    public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    raw_bytes: String,
    #[serde(default)]
    valid_for: Option<RawTimeRange>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthority {
    cert_chain: CertChain,
    #[serde(default)]
    valid_for: Option<RawTimeRange>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertChain {
    certificates: Vec<RawCert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCert {
    raw_bytes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTimeRange {
    start: String,
    #[serde(default)]
    end: Option<String>,
}

#[cfg(test)]
mod trust_tests {
    use super::*;

    #[test]
    fn rfc3339_parses_z_fraction_and_offset() {
        // Canonical proto3 Timestamp (Z, millis) and an offset form.
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_rfc3339_secs("2027-01-15T08:00:00.000Z").unwrap(),
            1_800_000_000
        );
        // +01:00 is one hour EAST of UTC, so the UTC instant is one hour earlier.
        assert_eq!(
            parse_rfc3339_secs("2027-01-15T09:00:00+01:00").unwrap(),
            1_800_000_000
        );
    }

    #[test]
    fn rfc3339_rejects_malformed() {
        for s in [
            "",
            "2027-01-15",
            "2027-01-15T08:00:00",  // no zone
            "2027-13-15T08:00:00Z", // month 13
            "2027-01-15T08:00:00.Z",
            "2027/01/15T08:00:00Z",
        ] {
            assert!(parse_rfc3339_secs(s).is_err(), "must reject {s:?}");
        }
    }

    #[test]
    fn time_range_absent_end_is_open() {
        let open = TimeRange {
            start: 100,
            end: None,
        };
        assert!(open.contains(100) && open.contains(i64::MAX));
        assert!(!open.contains(99));
        let bounded = TimeRange {
            start: 100,
            end: Some(200),
        };
        assert!(bounded.contains(100) && bounded.contains(200)); // inclusive
        assert!(!bounded.contains(201));
    }
}
