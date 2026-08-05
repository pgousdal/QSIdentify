# Protocol safety policy

QSIdentify is not a radio programmer.

Every outbound logical command is declared in `protocol/commands.py` with an
explicit safety class. The only M0.2 command is the read-only identification
query. The probe checks the classification before encoding or transmitting it.
The CLI has no input that becomes transmit bytes.

M1.3 adds no command descriptor and no serial operation. Registry and
contribution commands are offline. The audit pins the packaged command inventory
to an approved SHA-256 snapshot; `0x0514 / identify-handshake` remains the only
executable Quansheng transmit command.

Prohibited capabilities include EEPROM writes, firmware chunks, flash erase,
reset/reboot, mode changes, arbitrary frames, and automatic bootloader entry.
Passive recognition of an already-returned `18 05` bootloader message does not
authorize any response to it.

A future command may be added only when its behavior is supported by primary or
reproducible evidence, it is demonstrably read-only, and byte-level, malformed,
capture, and allowlist safety tests cover it. Commands that alter persistent
state or operating mode are outside this project's scope.

Transport uses explicit idle and total timeouts, a strict stream-size ceiling,
a complete write and flush, stale input/output reset, and bounded repeated
reads. Tests inject fake serial connections and never require hardware.

`monitor` is passive and performs zero writes. `matrix` is bounded to four line
states across at most three settle delays and always uses the same allowlisted
identification command. DTR and RTS are applied once per attempt; no state is
claimed to be universally correct.

M0.3 does not add any serial command. Its firmware advisory reads existing
captures, packaged JSON metadata and explicit user input only. It cannot fetch,
read, decrypt, pack, unpack, modify, select, upload or flash firmware. It does
not invoke browser flashers, vendor tools, k5prog, or any comparable utility.

M1.1 audit, release, fixture and capture commands are offline and never open a
serial port. The allowlist remains exactly one read-only identification command.
