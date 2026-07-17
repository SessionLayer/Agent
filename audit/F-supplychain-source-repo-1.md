# F-supplychain-source-repo-1: provenance source-repo used a bare substring match
- Severity: low
- Status: Verified-Fixed
- Area: supplychain

## Summary
`check_provenance` matched the provenance source-repo refs with `.contains(source_repo_uri)`,
so `…/SessionLayer/Agent-evil` would substring-match `…/SessionLayer/Agent`. Not
exploitable (the authoritative repo gate is the `==` on the Fulcio source-repo OID
in `verify_identity`, plus the signature requirement), but loose.

## Fix
Match exactly or as a path prefix (`repo` or `repo/…`), never a bare substring.
(T3 redteam NEW #3.)
