# Public Python API

The supported high-level API is:

```python
from qsidentify import identify

result = identify("/dev/ttyUSB0")
print(result.driver.id)
print(result.report.reported_version)
```

`identify()` selects a compiled-in read-only driver (`quansheng` by default),
performs one bounded identification probe and returns immutable
`IdentificationResult`. The result exposes `DriverInfo` and `ProbeReport`, not
the serial connection, write methods or internal transport exchange.

Optional keyword arguments configure the driver ID, baud rate, total and idle
timeouts, settle delay, DTR and RTS. Invalid driver IDs fail without opening a
port. The API performs no network access, telemetry, dynamic plugin discovery or
arbitrary frame transmission.

`qsidentify.drivers()` returns the deterministic tuple of compiled-in drivers.
`DriverInfo` and `IdentificationResult` are public immutable models. Modules
under `qsidentify.transport` and driver implementation packages remain internal
architecture and are not required for normal identification.
