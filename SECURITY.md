# Security policy

Report a vulnerability through GitHub's private vulnerability reporting: the
**Security** tab above, then **Report a vulnerability**. That opens a thread
only you and the maintainers can read. Do not open a public issue, pull
request, or discussion for a security finding.

[SessionLayer's vulnerability disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
is the single authority for every repository in this organization: what to
include in a report, full scope, embargo and credit, and how to verify that
the release you installed is the build the advisory named. Read it before
reporting.

## Scope in this repository

The SessionLayer Agent runs on every managed node as a non-root, outbound-only
connector, and it splices SSH ciphertext without ever seeing session
plaintext.

In scope: join and identity renewal, dial-back and splice, the offline
Sigstore verifier together with the install path it guards, the non-root and
sandbox enforcement, and `release.yml`. A defect in the verifier is a
supply-chain finding: `verify`, `update`, and `--verify-self` are what stop a
node from running an unverified or downgraded binary.

Not accepted here: test fixtures under `testing/` and committed test keys,
which are published so results reproduce. The policy lists the rest of the
out-of-scope set, including volumetric denial-of-service testing, anything
starting from a credential the threat model already assumes lost, and accepted
risks already documented in the trust model.

## Response targets

The [disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
carries the one timeline this organization keeps, from acknowledgement through
triage, fix and embargo, and it covers every repository including this one.
Advisories credit you unless you ask to stay anonymous, and request a CVE for
findings rated moderate or above. There is no bug bounty.
