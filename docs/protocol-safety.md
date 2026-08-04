# Protocol safety policy

QSIdentify is not a radio programming tool.

Outbound traffic is controlled by a compile-time allowlist in
`protocol/commands.py`. The CLI cannot accept arbitrary hexadecimal transmit
payloads.

Before a new command may be added:

1. Its behavior must be documented from a primary source or reproducible trace.
2. It must be demonstrated to be read-only.
3. A byte-level unit test must be added.
4. The safety test suite must pass.
5. The command must not alter mode, EEPROM, flash or persistent configuration.
