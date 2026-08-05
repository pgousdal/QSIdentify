# Contribution packages

Contribution schema 1 is a deterministic ZIP containing `manifest.json`,
sanitized evidence bundles and optional declaration JSON. Members are sorted,
timestamps are fixed, permissions are normalized, compression is stable and
SHA-256 checksums cover every bundle.

Review rejects absolute or parent-traversal paths, backslash paths, symlinks,
duplicate names, executable bits, scripts, firmware/binary image extensions,
network URLs, digest mismatches, unsupported schemas and unsanitized captures.
Photographs are not embedded; a declaration may carry a digest only.

`contribution-review` classifies an archive as `safe-to-import`,
`safe-with-warnings`, `requires-manual-review`, or `rejected`. Review has no side
effects. `registry-import-contribution --dry-run` shows the plan; a real atomic
import requires `--yes`. No upload functionality exists.
