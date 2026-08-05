# Evidence registry

Evidence registry schema 1 is deterministic offline JSON. It contains registry
identity and timestamps, QSIdentify provenance, bundle records, pseudonymous
device records, physical declaration records, candidate discriminators, review
events and a digest. Writes use atomic replacement, sorted keys and records, and
a newline at EOF.

Bundle ID, content digest, electronic fingerprint, device ID, capture ID and
probe-run/experiment ID are distinct. Exact identity, content duplication, a
shared fingerprint and a probable shared evidence set are reported separately.
A fingerprint match never merges device records.

Device IDs are hashes of an explicit local pseudonym. They are not derived from
USB serials, usernames, hostnames, paths or personal information. A local label
and declarations are user metadata. Bundles may remain unassociated.

Lifecycle:

1. Create a registry.
2. Validate sanitized bundles or contribution packages.
3. Inspect a deterministic import plan.
4. Explicitly approve atomic mutation.
5. Analyze counts, conflicts and candidates descriptively.
6. Export a separate catalog proposal for human review.

Removal deletes the active bundle record but appends an audit event. Inspection
commands never mutate. Registry operations do not access radio ports, networks,
or production catalogs.
