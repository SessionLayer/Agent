# F-supplychain-ci-injection-1: GitHub Actions script injection via ${{ github.ref_name }}
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
Agent + Gateway release.yml interpolated `${{ github.ref_name }}` directly into a
`run:` shell in a job holding id-token/attestations/contents:write (the keyless
signing identity). A crafted tag (git refs allow `$ ( ) ; \` " |`) could run
arbitrary commands as the release signer. (Needs tag-push access → medium.)

## Fix
Pass the ref via a step `env: TAG:` and reference `"$TAG"` (mirrors CP/Dashboard,
which were already correct). (T3 security MED-1 / reliability F7.)
