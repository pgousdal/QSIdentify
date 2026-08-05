# Compatibility policy

Documented Python imports, signatures, immutable result fields, CLI names, JSON
fields and exit categories follow semantic versioning. Validation exits 0 for
valid, 1 for valid-with-warnings, 3 for invalid, 4 for unsupported schema, and 5
for unknown driver. JSON commands write JSON only to stdout.

`qsidentify.protocol`, `qsidentify.advisory`, and `qsidentify.catalog` are
deprecated since 1.1, emit no normal CLI warning, and will not be removed before
2.0. Prefer the high-level API or `qsidentify.drivers.quansheng`.
