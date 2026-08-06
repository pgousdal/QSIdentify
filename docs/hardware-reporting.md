# Hardware Reporting Checklist

Use this checklist when reporting a radio, cable, capture, or possible hardware
relationship.

1. Use only the standard read-only identification mode.
2. Do not enter firmware-update mode unless the report concerns passive
   bootloader observation specifically.
3. Stop ModemManager, CHIRP, K5TOOL, k5prog, and other serial consumers before
   probing.
4. Verify the selected serial port before transmitting the allowlisted query.
5. Do not move or force the connector during automated matrix tests.
6. Sanitize captures before publishing them.
7. Report the cable VID:PID when available.
8. Separate observed bytes from user declarations and catalog assumptions.
9. State whether the radio was opened and whether the MCU or PCB marking was
   visually inspected.
10. Preserve unknown, contradictory, and incomplete responses rather than
    replacing them with a model guess.

Use the hardware issue template for physical observations. A firmware string or
marketing name does not prove MCU family, PCB revision, hardware revision,
flash geometry, or bootloader revision.
