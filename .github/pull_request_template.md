## Summary


## Safety And Scope

- [ ] No new radio command or arbitrary frame transmission was added.
- [ ] No EEPROM, firmware, erase, reset, reboot, or bootloader-entry behavior was added.
- [ ] Unknown responses and uncertainty remain preserved.
- [ ] No network access, telemetry, dynamic plugins, or downloads were added.

## Evidence And Privacy

- [ ] Captures and fixtures are sanitized.
- [ ] Provenance is documented.
- [ ] No firmware binaries, hostnames, usernames, USB serials, or private paths are included.

## Validation

- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy src`
- [ ] `pytest`
- [ ] `python -m compileall -q src tests`
- [ ] `python -m build`
- [ ] `git diff --check`

## Limitations

Describe unresolved evidence, hardware uncertainty, compatibility assumptions,
or follow-up review needed.
