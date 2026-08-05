# Evidence probes

Named probes are packaged, deterministic definitions. The default
`firmware-identification` probe performs one existing identification request.
`repeated-firmware-identification` is experimental and repeats only that same
allowlisted request, with a hard maximum of 20 attempts. The passive connection
observation transmits nothing. Bootloader identification and protocol capability
queries remain unavailable because no documented safe request is curated.

`qsidentify evidence-probe PORT` prints or returns the driver, definition,
command IDs, safety class, repeat count, and evidence targets. Experimental
probes require explicit `--probe`. Reads remain bounded by transport timeouts.
