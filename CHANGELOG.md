# Changelog

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
