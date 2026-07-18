//! Minimal DER surgery for the RFC 6962 precertificate reconstruction: slice the
//! TBSCertificate out of a Certificate and rebuild it with one extension removed.
//! Verifying an *embedded* SCT means signing-checking the log's signature over
//! the precert — the final leaf's TBS with the SCT-list extension stripped — so
//! the verifier has to reproduce those bytes exactly. Hand-rolled (no DER
//! re-encoder dependency, NFR-7); every enclosing length is re-encoded from
//! scratch, so there is no delta arithmetic to get wrong.

use super::error::VerifyError;

fn err(msg: impl Into<String>) -> VerifyError {
    VerifyError::Sct(format!("DER: {}", msg.into()))
}

/// `(tag, header_len, content_len)` of the definite-length TLV at the start of
/// `der`. Rejects indefinite length (not valid DER) and >4-byte lengths.
pub(super) fn read_tlv(der: &[u8]) -> Result<(u8, usize, usize), VerifyError> {
    let tag = *der.first().ok_or_else(|| err("empty"))?;
    let l0 = *der.get(1).ok_or_else(|| err("truncated length"))?;
    if l0 & 0x80 == 0 {
        return Ok((tag, 2, l0 as usize));
    }
    let n = (l0 & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(err("unsupported length form"));
    }
    let mut len = 0usize;
    for &b in der
        .get(2..2 + n)
        .ok_or_else(|| err("truncated long length"))?
    {
        len = (len << 8) | b as usize;
    }
    Ok((tag, 2 + n, len))
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut be: Vec<u8> = len.to_be_bytes().to_vec();
    while be.first() == Some(&0) {
        be.remove(0);
    }
    let mut out = vec![0x80 | be.len() as u8];
    out.extend_from_slice(&be);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Split a SEQUENCE/SET body into its top-level TLV element slices.
fn elements(mut body: &[u8]) -> Result<Vec<&[u8]>, VerifyError> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let (_, hdr, len) = read_tlv(body)?;
        let end = hdr.checked_add(len).ok_or_else(|| err("length overflow"))?;
        let elem = body.get(..end).ok_or_else(|| err("element truncated"))?;
        out.push(elem);
        body = &body[end..];
    }
    Ok(out)
}

/// The TBSCertificate DER = the first element of the Certificate SEQUENCE.
pub(super) fn tbs_of_certificate(cert_der: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (tag, hdr, len) = read_tlv(cert_der)?;
    if tag != 0x30 {
        return Err(err("certificate is not a SEQUENCE"));
    }
    let body = cert_der
        .get(hdr..hdr + len)
        .ok_or_else(|| err("certificate truncated"))?;
    let first = elements(body)?
        .into_iter()
        .next()
        .ok_or_else(|| err("certificate has no tbsCertificate"))?;
    if first.first() != Some(&0x30) {
        return Err(err("tbsCertificate is not a SEQUENCE"));
    }
    Ok(first.to_vec())
}

/// Rebuild `tbs_der` with the single X.509 extension whose OID DER equals
/// `oid_der` removed from the `[3] EXPLICIT Extensions` field. Errors if the
/// extension is absent (the caller wants it gone precisely because it is there).
pub(super) fn remove_extension(tbs_der: &[u8], oid_der: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (tag, hdr, len) = read_tlv(tbs_der)?;
    if tag != 0x30 {
        return Err(err("tbs is not a SEQUENCE"));
    }
    let body = tbs_der
        .get(hdr..hdr + len)
        .ok_or_else(|| err("tbs truncated"))?;

    // Walk the TBS fields, byte-copying everything before the `[3]` extensions
    // wrapper (0xA3) verbatim, then re-encode the wrapper without the target ext.
    let mut prefix = Vec::new();
    let mut ext_wrapper: Option<&[u8]> = None;
    for elem in elements(body)? {
        if elem.first() == Some(&0xA3) && ext_wrapper.is_none() {
            ext_wrapper = Some(elem);
        } else {
            prefix.extend_from_slice(elem);
        }
    }
    let wrapper = ext_wrapper.ok_or_else(|| err("tbs has no extensions"))?;

    let (_, wh, wl) = read_tlv(wrapper)?;
    let ext_seq = wrapper
        .get(wh..wh + wl)
        .ok_or_else(|| err("wrapper truncated"))?;
    let (stag, sh, sl) = read_tlv(ext_seq)?;
    if stag != 0x30 {
        return Err(err("extensions is not a SEQUENCE"));
    }
    let seq_body = ext_seq
        .get(sh..sh + sl)
        .ok_or_else(|| err("ext seq truncated"))?;

    let mut kept = Vec::new();
    let mut removed = false;
    for ext in elements(seq_body)? {
        if extension_oid_matches(ext, oid_der)? {
            removed = true;
        } else {
            kept.extend_from_slice(ext);
        }
    }
    if !removed {
        return Err(err("target extension not present"));
    }

    let new_wrapper = tlv(0xA3, &tlv(0x30, &kept));
    let mut new_tbs_body = prefix;
    new_tbs_body.extend_from_slice(&new_wrapper);
    Ok(tlv(0x30, &new_tbs_body))
}

/// Whether the first element of an `Extension ::= SEQUENCE { OID, ... }` is `oid_der`.
fn extension_oid_matches(ext: &[u8], oid_der: &[u8]) -> Result<bool, VerifyError> {
    let (tag, hdr, len) = read_tlv(ext)?;
    if tag != 0x30 {
        return Err(err("extension is not a SEQUENCE"));
    }
    let inner = ext
        .get(hdr..hdr + len)
        .ok_or_else(|| err("extension truncated"))?;
    let oid = elements(inner)?
        .into_iter()
        .next()
        .ok_or_else(|| err("extension has no OID"))?;
    Ok(oid == oid_der)
}
