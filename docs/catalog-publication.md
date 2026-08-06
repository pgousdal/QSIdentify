# Catalog Publication

Production catalogs are treated as immutable release inputs. A catalog
proposal is a draft containing proposed entries, supporting bundle and device
IDs, thresholds, rationale and review history. Proposal review and proposal
approval are separate explicit operations.

Publication packages are deterministic ZIP archives containing only:

- `manifest.json`
- `catalog.json`
- `reviews.json`
- `references.json`
- `checksums.json`

The archive has fixed timestamps, sorted members and SHA-256 member checksums.
Verification rejects traversal paths, duplicates, executable members, network
URLs, firmware binary references, missing members and checksum mismatches. It
contains no firmware binaries, captures or user metadata.

Every publication record certifies catalog entry IDs, supporting bundle IDs,
device IDs, reviewer IDs, review IDs and policy thresholds satisfied. Building
a package does not directly modify a production catalog.
