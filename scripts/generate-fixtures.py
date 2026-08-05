from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from qsidentify import __version__
from qsidentify.capture import build_capture, write_capture
from qsidentify.drivers import get_driver
from qsidentify.drivers.quansheng.frame import (
    FRAME_FOOTER,
    FRAME_HEADER,
    encode_frame,
    xor_transform,
)
from qsidentify.models import Exchange, LineState, PortInfo, ReadChunk
from qsidentify.probe import _result

ROOT = Path("tests/fixtures")
CAPTURES = ROOT / "captures"
STREAMS = ROOT / "streams"
CREATED = "2000-01-01T00:00:00+00:00"


def legacy_frame(payload: bytes) -> bytes:
    return (
        FRAME_HEADER
        + bytes((len(payload), 0))
        + xor_transform(payload + b"\xff\xff")
        + FRAME_FOOTER
    )


def capture_for(name: str, response: bytes, *, physical: bool = False):  # type: ignore[no-untyped-def]
    driver = get_driver("quansheng")
    command = driver.identify()
    request = driver.encode(command)
    analysis = driver.analyze_stream(response, request)
    exchange = Exchange(
        command.payload,
        request,
        (ReadChunk(1, 1.0, response),) if response else (),
        response,
        analysis,
        LineState(False, False),
        0.1,
        3.0,
        0.2,
    )
    result = _result(PortInfo("/dev/ttyUSB0", vid=0x1A86, pid=0x7523), exchange, 38400, driver)
    capture = build_capture(result, created_utc=CREATED)
    metadata = {
        "fixture_kind": "sanitized-physical-capture"
        if physical
        else "synthetic-regression-capture",
        "radio_family": "Quansheng UV-K5 family",
        "reported_firmware": "2.01.36" if physical else capture.report.reported_version,
        "reported_model": "UV-K5(8)" if physical else None,
        "sanitization": [
            "normalized timestamp",
            "removed USB serial number",
            "normalized device path",
        ]
        if physical
        else [],
        "source": "physical hardware validation" if physical else "deterministic test construction",
        "sanitized": True,
    }
    capture = replace(capture, qsidentify_version=__version__, capture_metadata=metadata)
    path = CAPTURES / f"{name}.json"
    write_capture(path, capture)
    (STREAMS / f"{name}.hex").write_text(response.hex(" ") + "\n")
    return path, capture


def main() -> None:
    CAPTURES.mkdir(parents=True, exist_ok=True)
    STREAMS.mkdir(parents=True, exist_ok=True)
    driver = get_driver("quansheng")
    tx = driver.encode(driver.identify())
    valid_unknown = encode_frame(b"\x99\x01unknown")
    firmware = encode_frame(b"\x15\x052.01.36\x00")
    physical = legacy_frame(b"\x15\x05\x24\x002.01.36\x00")
    bootloader = encode_frame(b"\x18\x05BL1.0\x00")
    invalid = bytearray(encode_frame(b"\x15\x05bad\x00"))
    invalid[-3] ^= 0x01
    cases = {
        "bootloader-response": bootloader,
        "echo-only": tx,
        "incomplete-frame": firmware[:-3],
        "invalid-checksum": bytes(invalid),
        "no-response": b"",
        "null-byte-response": b"\x00\x00\x00",
        "unframed-binary": bytes.fromhex("00 20 00 02 29 10 00 14"),
        "valid-firmware": firmware,
        "valid-unknown-frame": valid_unknown,
        "uv-k5-8-2.01.36": physical,
    }
    entries = []
    generated = {}
    for name, response in sorted(cases.items()):
        path, capture = capture_for(name, response, physical=name == "uv-k5-8-2.01.36")
        generated[name] = (path, capture)
        entries.append(
            {
                "classification": capture.stream_classification.value,
                "driver_id": capture.driver_id,
                "message_type": capture.report.message_type.value,
                "path": path.relative_to(ROOT).as_posix(),
                "provenance": capture.capture_metadata["fixture_kind"],
                "reported_version": capture.report.reported_version,
                "schema_version": capture.schema_version,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    source_path, source = generated["valid-firmware"]
    v2 = source.to_dict()
    v2["schema_version"] = 2
    v2.pop("driver_id")
    v2.pop("driver_version")
    v2.pop("capture_metadata")
    v2_path = CAPTURES / "schema-v2.json"
    v2_path.write_text(json.dumps(v2, indent=2, sort_keys=True) + "\n")
    entries.append(
        {
            "classification": source.stream_classification.value,
            "driver_id": "quansheng",
            "message_type": source.report.message_type.value,
            "path": v2_path.relative_to(ROOT).as_posix(),
            "provenance": "synthetic-schema-compatibility",
            "reported_version": source.report.reported_version,
            "schema_version": 2,
            "sha256": hashlib.sha256(v2_path.read_bytes()).hexdigest(),
        }
    )
    report = source.report.to_dict()
    v1 = {
        "baud_rate": 38400,
        "checksum_status": source.checksum_status.value if source.checksum_status else None,
        "created_utc": CREATED,
        "decoded_payload_hex": source.decoded_payload_hex,
        "encoded_transmitted_frame_hex": source.encoded_transmitted_frame_hex,
        "leading_response_bytes_hex": source.leading_bytes_hex,
        "logical_request_payload_hex": source.logical_request_payload_hex,
        "port": report["port"],
        "probe_report": {**report, "schema_version": 1},
        "qsidentify_version": "0.1.1",
        "received_frame_hex": source.received_frame_hex,
        "safety": source.safety,
        "schema_version": 1,
        "timeout": 3.0,
    }
    v1_path = CAPTURES / "schema-v1.json"
    v1_path.write_text(json.dumps(v1, indent=2, sort_keys=True) + "\n")
    entries.append(
        {
            "classification": source.stream_classification.value,
            "driver_id": "quansheng",
            "message_type": source.report.message_type.value,
            "path": v1_path.relative_to(ROOT).as_posix(),
            "provenance": "synthetic-schema-compatibility",
            "reported_version": source.report.reported_version,
            "schema_version": 1,
            "sha256": hashlib.sha256(v1_path.read_bytes()).hexdigest(),
        }
    )
    manifest = {"entries": sorted(entries, key=lambda item: item["path"]), "schema_version": 1}
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
