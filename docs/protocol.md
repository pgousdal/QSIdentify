# Quansheng framing in M0.1

QSIdentify models normal frames as:

```text
AB CD | payload length (uint8) | reserved 00 | protected payload + CRC | DC BA
```

The protected region is XORed with the repeating immutable key:

```text
16 6c 14 e6 2e 91 0d 40 21 35 d5 40 13 03 e9 80
```

The outbound checksum is standard CRC-16/XMODEM (polynomial `0x1021`, initial
value zero, no reflection, no final XOR), serialized little-endian. For
`123456789` it is `31c3`.

The logical, read-only identification payload is:

```text
14 05 04 00 6a 39 57 64
```

Its byte-exact encoded frame is:

```text
ab cd 08 00 02 69 10 e6 44 a8 5a 24 b9 a9 dc ba
```

Decoding validates header, the zero reserved byte, footer, declared length, the
255-byte maximum payload size, completeness, and checksum. Some radio responses
put decoded `ff ff` in the checksum field.
M0.1 labels this `accepted-legacy-ff-ff`, never `valid`; a matching calculated
CRC is labeled `valid`. Mismatches are invalid frames. Original bytes and
unknown decoded payload bytes remain evidence.

Text extraction happens only after framing and deobfuscation. Payloads beginning
with message bytes `18 05` are passively classified as bootloader responses. No
bootloader command is transmitted. A bootloader version is reported only when
printable version evidence is present.

These rules are validated against deterministic fixtures and available
reverse-engineering evidence, not an in-repository physical-radio capture.
