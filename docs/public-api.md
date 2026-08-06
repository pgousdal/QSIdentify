# Public Python API

The supported high-level API is:

```python
from qsidentify import identify

result = identify("/dev/ttyUSB0")
print(result.driver.id)
print(result.report.reported_version)
```

The stable synchronous registry surface is:

```python
from qsidentify.registry import (
    add_evidence_bundle,
    analyze_registry,
    create_registry,
    load_registry,
    validate_registry,
)
```

Registry models and operation results are frozen dataclasses. Functions are
offline and deterministically order records. `write_registry` is intentionally
not in the minimal public surface; CLI mutation uses atomic replacement.
`RegistryError`, `RegistrySchemaError`, and `DuplicateEvidenceError` describe
expected failures. Calls are synchronous and do not expose mutable dictionaries
or serial objects. Concurrent writers are not coordinated; callers must provide
external locking if multiple processes share one registry.

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

The API is synchronous. Callers coordinate concurrent access to one device.
`identify()` may raise `KeyError` for an unknown driver, `RuntimeError` or its
transport subclasses, `OSError`, or `ValueError`. Documented parameters and the
immutable `IdentificationResult(driver, report)` fields follow semantic
versioning.

The M2.0 governance API is available from `qsidentify`:

```python
from qsidentify import (
    approve_proposal,
    build_publication,
    create_proposal,
    create_review,
    verify_publication,
)
```

Governance operations accept and return frozen ledger models. They are offline,
append-only operations; publication verification returns a structured result
and never extracts or executes archive members.
