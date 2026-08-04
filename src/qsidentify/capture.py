from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Capture, Confidence, Evidence, PortInfo, ProbeReport, ProbeResult


def build_capture(result: ProbeResult) -> Capture:
    return Capture(
        schema_version=1,
        created_utc=datetime.now(UTC).replace(microsecond=0).isoformat(),
        port=result.report.port,
        baud_rate=result.report.baud_rate,
        request_hex=result.exchange.request.hex(),
        response_hex=result.exchange.response.hex(),
        report=result.report,
        metadata={"safety": "read-only"},
    )


def write_capture(path: Path, capture: Capture) -> None:
    payload = json.dumps(capture.to_dict(), indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def read_capture(path: Path) -> Capture:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    port_raw = raw["port"]
    port = PortInfo(**port_raw)

    report_raw = raw["report"]
    report = ProbeReport(
        schema_version=report_raw["schema_version"],
        qsidentify_version=report_raw["qsidentify_version"],
        port=PortInfo(**report_raw["port"]),
        baud_rate=report_raw["baud_rate"],
        operating_mode=report_raw["operating_mode"],
        response_received=report_raw["response_received"],
        reported_version=report_raw.get("reported_version"),
        detected_protocol=report_raw.get("detected_protocol"),
        inferred_family=report_raw.get("inferred_family"),
        confidence=Confidence(report_raw["confidence"]),
        evidence=tuple(Evidence(**item) for item in report_raw.get("evidence", [])),
        warnings=tuple(report_raw.get("warnings", [])),
    )

    return Capture(
        schema_version=raw["schema_version"],
        created_utc=raw["created_utc"],
        port=port,
        baud_rate=raw["baud_rate"],
        request_hex=raw["request_hex"],
        response_hex=raw["response_hex"],
        report=report,
        metadata=dict(raw.get("metadata", {})),
    )
