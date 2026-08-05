# Release process

Run Ruff lint/format, Mypy, Pytest, compileall, build and `git diff --check`.
Run `fixture-validate`, `firmware-catalog-validate`, `audit`, and `release-info`.
Inspect wheel/sdist members, then install each local artifact into a fresh venv
and test version, driver, catalog, public imports, and compatibility imports.
Compare clean builds by normalized member content; archive timestamps may
prevent byte identity, so no stronger reproducibility claim is made.
