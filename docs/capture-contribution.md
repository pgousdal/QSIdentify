# Capture contribution

Create a capture with `probe --capture` or `monitor --capture`, then run
`capture-sanitize`, `capture-inspect`, and `capture-validate`. Sanitization
normalizes timestamp/device metadata and removes USB serial and descriptive host
fields while preserving every request, response and chunk byte. It never
overwrites its input. Physical derivatives must list transformations and must
not infer MCU or PCB from firmware strings. Committed fixtures are sorted and
SHA-256 recorded in `tests/fixtures/manifest.json`; run `fixture-validate`.
