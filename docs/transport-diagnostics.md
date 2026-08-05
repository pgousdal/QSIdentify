# Transport diagnostics

## Physical observations

Physical testing used a Quansheng UV-K5(8) and two CH340 programming cables.
With the cable disconnected, no response was observed. With the radio side
connected and the radio off, the adapter sometimes returned unrelated leading
bytes followed by an exact copy of the 16-byte transmitted identification
frame. M0.2 calls this a serial transmit echo and does not decode it as a radio
response.

With the radio on, tests observed no bytes, null-only streams and short variable
binary streams such as `00 00 02 00 2a 00`. Ten repetitions differed in length
and content. This is insufficient evidence for a stable alternative protocol.
Possible causes include fragmentation, timing, synchronization, line state,
local echo, electrical noise or an unknown transport; M0.2 does not choose
between them.

## Evidence collection

A serial read chunk records one non-empty operating-system read and its
monotonic offset. Chunks are useful timing evidence but are never protocol
boundaries. The combined stream is analyzed independently for echoes, every
`ab cd` frame candidate, null-only data and remaining unframed bytes.

`--settle-delay` waits after buffer reset and line-state application before the
allowlisted probe. `--dtr` and `--rts` accept `auto`, `on` and `off`; these are
controlled experiments, not recommended universal settings.

Use `qsidentify monitor PORT` to collect spontaneous data without writing. Use
`qsidentify matrix PORT` for a bounded DTR/RTS experiment, and `qsidentify
compare FILE...` to compare lengths, exact matches, prefixes/suffixes, common
positions, byte frequency, fingerprints, echo and null proportions. Frequency
is descriptive evidence and does not establish protocol meaning.

## Classifications

- `no-response`: no bytes before total timeout
- `echo-only`: one or more complete TX copies and no other bytes
- `transmit-echo`: complete TX echo plus unparsed transport bytes
- `partial-transmit-echo`: an unconsumed suffix matches the start of TX
- `echo-followed-by-response`: an echo and a valid non-echo frame
- `null-byte-response`: every received byte is zero
- `unframed-binary-response`: binary evidence without a complete frame
- `incomplete-response`: a truncated `ab cd` candidate
- `invalid-frame`: a complete candidate failed framing or checksum validation
- `framed-response`: at least one valid non-echo frame

Transport classification is separate from protocol message type. A framed
response may then decode as firmware identification, bootloader response or a
valid unknown frame. Operating mode, reported version, inferred family and
confidence remain independent report fields.
