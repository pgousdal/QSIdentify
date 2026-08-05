# Release process

Run Ruff lint/format, Mypy, Pytest, compileall, build and `git diff --check`.
Run `fixture-validate`, `firmware-catalog-validate`, `audit`, and `release-info`.
Inspect wheel/sdist members, then install each local artifact into a fresh venv
and test version, driver, catalog, public imports, and compatibility imports.
Compare clean builds by normalized member content; archive timestamps may
prevent byte identity, so no stronger reproducibility claim is made.

For 1.3, also validate an empty registry fixture, create and review a
contribution, test a dry-run import and an explicitly approved import, inspect
the command-inventory snapshot audit, and verify registry/contribution schema
versions in `release-info`. Contribution ZIP members must retain fixed dates,
sorted names and normalized non-executable permissions in both installed
artifacts.
