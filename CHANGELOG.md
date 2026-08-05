# Changelog

## 0.2.0 - 2026-08-04

- collect complete bounded RX streams until idle or total timeout
- record timestamped serial read chunks and explicit DTR/RTS state
- detect complete, repeated and partial transmit echoes without treating them as responses
- classify null-only, unframed binary, incomplete and invalid framed streams
- scan past malformed candidates for later valid Quansheng frames
- add passive `monitor`, controlled `matrix` and offline `compare` commands
- upgrade captures to schema v2 while retaining schema-v1 loading
- document physical UV-K5(8)/CH340 observations without inferring a new protocol

## 0.1.1 - 2026-08-04

- encode the read-only identify payload in a validated Quansheng frame
- add CRC-16/XMODEM and repeating-XOR byte fixtures
- distinguish verified CRC from accepted legacy `ff ff` responses
- replace generic serial reads with bounded frame-aware transport
- decode text only from deobfuscated payloads
- recognize passive `18 05` bootloader evidence
- consolidate immutable domain models and explicit serialization
- validate and atomically write deterministic capture schema v1
- harden CLI errors, JSON-only output, trace details, and doctor checks
- expand hardware-free protocol, malformed-input, transport, capture, and safety tests
