# Capture contribution

Create a capture with `probe --capture` or `monitor --capture`, then run
`capture-sanitize`, `capture-inspect`, and `capture-validate`. Sanitization
normalizes timestamp/device metadata and removes USB serial and descriptive host
fields while preserving every request, response and chunk byte. It never
overwrites its input. Physical derivatives must list transformations and must
not infer MCU or PCB from firmware strings. Committed fixtures are sorted and
SHA-256 recorded in `tests/fixtures/manifest.json`; run `fixture-validate`.

M1.3 contribution ZIPs wrap sanitized evidence bundles without changing their
protocol bytes. Run `contribution-create`, `contribution-review`, and then use
`registry-import-contribution --dry-run`. Mutation requires explicit `--yes`.
Review never imports automatically and rejects traversal, absolute paths,
symlinks, executables, firmware binaries, URLs, duplicate members and digest
failures.
