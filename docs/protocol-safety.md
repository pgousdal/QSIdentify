# Protocol safety policy

QSIdentify is not a radio programmer.

Every outbound logical command is declared in `protocol/commands.py` with an
explicit safety class. The only M0.1 command is the read-only identification
query. The probe checks the classification before encoding or transmitting it.
The CLI has no input that becomes transmit bytes.

Prohibited capabilities include EEPROM writes, firmware chunks, flash erase,
reset/reboot, mode changes, arbitrary frames, and automatic bootloader entry.
Passive recognition of an already-returned `18 05` bootloader message does not
authorize any response to it.

A future command may be added only when its behavior is supported by primary or
reproducible evidence, it is demonstrably read-only, and byte-level, malformed,
capture, and allowlist safety tests cover it. Commands that alter persistent
state or operating mode are outside this project's scope.

Transport uses explicit timeouts, a strict frame-size ceiling, a complete write
and flush, stale-input reset, and bounded frame reads. Tests inject fake serial
connections and never require hardware.
