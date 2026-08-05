# Hardware evidence

M0.3 tracks confidence separately for serial transport, protocol family,
firmware version, marketed model, hardware revision, MCU family and firmware
compatibility. One confirmed field does not make the others confirmed.

The packaged registry contains these conservative records:

- legacy/V1 UV-K5 family hardware: DP32G030
- V2-family hardware: PY32F030
- V3 hardware: PY32F071

`--model`, `--hardware-revision`, `--mcu` and `--pcb-marking` are explicit user
evidence. QSIdentify reports them as user supplied. A registry mapping from a
declared V1 revision to DP32G030 is a database inference, not an electronic MCU
detection. Conflicting revision, PCB and MCU input is never silently resolved.

Inspect revision and PCB markings directly and independently verify the MCU
before choosing firmware. Marketing labels and firmware strings do not prove
these properties.

A CHIRP backup is a configuration backup; it is not necessarily a complete,
recoverable firmware or calibration backup. Firmware images, configuration and
calibration data require separate handling. QSIdentify reads none of them.
