# F-gate-1: gate.sh finding parser fails OPEN on nonstandard front-matter
- Severity: low
- Status: Verified-Fixed
- Area: gate

Flagged by both `redteam-auditor` and `security-reviewer` in the Session One red-team pass.

## Issue
The original `scripts/gate.sh` "zero open medium+" check stripped the severity to
`[a-z]` after the label, so `- Severity: medium (needs confirm)` collapsed to
`mediumneedsconfirm` and matched none of `critical|high|medium` — silently
uncounted. A missing/misformatted `Status:` line also skipped the finding. In
each case an open medium+ finding would pass the merge-blocking gate. This is a
fail-open in the control that exists to police the findings themselves.

## Fix
`scripts/gate.sh` now extracts only the first alphabetic token after each label
(anchored, so trailing prose cannot dilute it) and parses **fail-closed**: a
medium+ finding that is not explicitly `Verified-Fixed`/`Accepted-Risk` blocks,
and any `F-*.md` with an unrecognizable severity is treated as MALFORMED and
blocks. Resolved/accepted medium+ findings are moved to `audit/closed/` (not
scanned by the glob) to stay consistent with the parent-scope idle hook.
