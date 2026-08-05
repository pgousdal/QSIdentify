# Electronic fingerprints

Fingerprint schema 1 uses canonical JSON and SHA-256. The ID has the form
`qsfingerprint:v1:sha256:DIGEST`. Its input is the driver ID, protocol family,
message types, reported firmware strings, stable payload values and masks,
response lengths, checksum behaviors, and observed bootloader/capability flags.

Timestamps, timing offsets, device paths, USB serial numbers, host metadata,
user labels, and variable payload values do not contribute. A matching
fingerprint means only that these observed fields match; it is not automatically
a hardware identity.

Stable positions have mask byte `ff`; missing or differing positions have `00`.
Fields are conservatively called stable or variable. They are not described as
random, nonce-like, timestamps, or monotonic without sufficient observations.
