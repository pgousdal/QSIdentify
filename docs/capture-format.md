# Capture format v1

A capture is deterministic JSON containing:

- schema version
- UTC creation timestamp
- serial-port metadata
- baud rate
- transmitted read-only request as hexadecimal
- received bytes as hexadecimal
- the interpreted probe report
- safety metadata

Captures should not include local usernames, home directories or unrelated
system information.

Unknown bytes must be preserved exactly.
