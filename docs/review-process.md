# Review Process

Reviews are immutable records containing a reviewer ID, timestamp, review type,
decision, rationale, supporting and contradicting evidence, confidence and
references. Decisions are `approve`, `reject`, `request-more-evidence`,
`superseded`, and `withdrawn`.

Blind reviews use an anonymized evidence view. Hostnames, contributor fields,
USB serials, filesystem paths and device paths are removed unless explicitly
shared. Blind publication records redact the reviewer identity as
`reviewer:anonymous` while retaining the review ID and decision.

Review is not identification. A review can confirm that evidence is internally
consistent without proving a hardware mapping. Conflicts and contradictory
evidence remain visible and must be addressed by a later review or a new
evidence submission.
