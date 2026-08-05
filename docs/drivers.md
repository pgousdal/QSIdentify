# Drivers

A driver subclasses `qsidentify.drivers.Driver` and exposes immutable
`DriverInfo`. Its responsibilities are:

- declare models, protocols and known VID/PID metadata;
- return only explicitly safety-classified commands;
- encode a command from its own allowlist;
- analyze a complete collected byte stream;
- decode and classify protocol frames;
- expose optional offline catalog/advisory metadata.

Drivers receive bytes and immutable captures. They must not import pyserial,
open devices, perform serial I/O, access the network, discover third-party code
or mutate evidence. Registration is explicit in `qsidentify.drivers`; ordering
is by stable driver ID and duplicate IDs are rejected.

The first driver is `quansheng`, version `1.0`. It contains the framing codec,
stream analyzer, decoder, `identify-handshake` allowlist, hardware registry,
firmware catalog and conservative compatibility advisory. Historical imports
under `qsidentify.protocol`, `qsidentify.advisory` and `qsidentify.catalog`
remain thin compatibility exports.

`DRIVER_API_VERSION` is independently versioned and currently `1`.
`DriverInfo.api_version` must match it or deterministic registration fails.

Adding another built-in family requires a self-contained driver package and one
explicit registry construction entry. Core transport, capture, CLI and advisory
presentation do not require protocol-specific branches.
