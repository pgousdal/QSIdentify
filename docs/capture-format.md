# Capture format v1

Capture files are UTF-8 JSON with sorted keys, two-space indentation, and a
trailing newline. Writes use a temporary file in the destination directory,
flush it, and atomically replace the destination.

Required top-level fields are:

- `schema_version` (exactly `1`)
- `created_utc` and `qsidentify_version`
- `port`, `baud_rate`, and `timeout`
- `logical_request_payload_hex`
- `encoded_transmitted_frame_hex`
- `leading_response_bytes_hex`
- `received_frame_hex`
- `decoded_payload_hex`
- `checksum_status`
- `probe_report`
- `safety`

Hex fields use canonical lowercase hexadecimal without separators. Leading
garbage, complete framed bytes, decoded payload bytes, and unknown data are kept
separately so transport and protocol evidence are not conflated.

Loading validates required fields, types, enums, canonical hex, and the schema
version. Malformed JSON and unsupported future versions produce controlled CLI
errors. `qsidentify decode FILE` decodes the stored received frame without
opening a serial port.

Captures include only selected-port metadata. A selected device path underneath
the local home directory is stored as `<redacted-home-path>`. Captures do not
collect usernames, unrelated device paths, network information, or telemetry.
