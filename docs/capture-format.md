# Capture format v2

Schema v2 is deterministic UTF-8 JSON with sorted keys, two-space indentation
and a trailing newline. Writes use a flushed temporary file followed by atomic
replacement.

It records the operation, selected-port metadata, baud rate, requested and
resulting DTR/RTS state, settle/total/idle timing, optional logical request and
encoded frame, timestamped read chunks, combined raw RX, leading bytes, exact
echo frames, all frame candidates, decoded valid frames, unparsed/trailing
bytes, stream classification, report and safety metadata.

Probe captures declare `operation: probe`, `transmit_performed: true`, the
`identify-handshake` command and `read-only` safety. Monitor captures declare
`operation: monitor`, `transmit_performed: false`, and contain no request bytes.
Loading enforces these relationships and recomputes derived stream analysis
from the exact raw bytes.

Schema-v1 M0.1 captures remain readable and are adapted to the richer in-memory
model. Unsupported schemas, invalid hexadecimal, malformed chunks and
inconsistent operation/safety fields produce controlled errors.

Selected device paths beneath the local home directory are redacted. Captures
do not collect unrelated device paths, usernames, network data or telemetry.

M0.3 does not change or rewrite schema-v2 captures. `firmware-advice --json`
emits a separate advisory object derived at invocation time. User-supplied
model, revision, MCU and PCB evidence are therefore not inserted into an old
capture unless a future explicit enriched-export format is introduced.
