# Versioning contracts

- Package version: `1.3.0`, from `_version.py`.
- Fingerprint schema: `1`, defining content-addressed electronic evidence.
- Hardware discriminator catalog schema: `1`, independent of verified mappings.
- Evidence registry schema: `1`, independent of bundle and fingerprint schemas.
- Contribution package schema: `1`, for deterministic offline ZIP manifests.
- Driver API version: `1`.
- Quansheng driver implementation version: `1.0`.
- Capture schemas: `1`, `2`, `3`.
- Catalog schema: `1`; firmware catalog content version: `2026.08`.

These are independent contracts; a package release need not change the others.
