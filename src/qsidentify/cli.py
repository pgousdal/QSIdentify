from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .capture import CaptureError, build_capture, read_capture, write_capture
from .comparison import compare_captures
from .contribution import (
    ContributionError,
    create_contribution,
    inspect_contribution,
    plan_contribution_import,
    review_contribution,
)
from .doctor import run_checks
from .drivers import default_driver, drivers, get_driver
from .evidence import (
    EvidenceError,
    compare_evidence,
    evidence_report,
    export_bundle,
    inspect_bundle,
    load_command_inventory,
    load_probe_definitions,
    validate_bundle,
)
from .evidence_registry import (
    DuplicateEvidenceError,
    RegistryError,
    add_evidence_bundle,
    analyze_registry,
    catalog_proposal,
    create_registry,
    detect_conflicts,
    load_registry,
    propose_discriminator,
    registry_matrix,
    remove_evidence_bundle,
    validate_registry,
    write_json_atomic,
    write_registry,
)
from .fixtures import validate_fixture_manifest
from .hardening import (
    ValidationStatus,
    audit_results,
    inspect_capture,
    release_info,
    sanitize_capture,
    validate_capture,
)
from .models import Capture, DecodedResponse, LineSetting, MessageType, ProbeResult
from .ports import choose_auto_port, find_port, list_serial_ports
from .probe import monitor_port, probe_port
from .transport import TransportError

app = typer.Typer(
    help="Read-only identification and diagnostics for Quansheng radios.",
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"QSIdentify {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """Read-only identification and transport diagnostics."""


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _hardware_input(
    model: str | None,
    hardware_revision: str | None,
    mcu: str | None,
    pcb_marking: str | None,
) -> dict[str, str | None]:
    return {
        "model": model,
        "hardware_revision": hardware_revision,
        "mcu": mcu,
        "pcb_marking": pcb_marking,
    }


def _firmware_advisory(
    capture: Capture,
    hardware_input: dict[str, str | None],
) -> Any:
    return get_driver(capture.driver_id).firmware_advice(capture, hardware_input)


def _print_advisory(advisory: Any) -> None:
    console.print("\n[bold]Firmware advisory[/bold]")
    console.print(f"  Observed firmware:   {advisory.observed_firmware or 'unknown'}")
    console.print(f"  Protocol family:     {advisory.protocol_family or 'unknown'}")
    model_suffix = " (user supplied)" if advisory.marketed_model else ""
    console.print(f"  Marketed model:      {advisory.marketed_model or 'unknown'}{model_suffix}")
    revision_suffix = (
        " (user supplied)"
        if advisory.confidence.hardware_revision.value == "user-supplied"
        else " (catalog inference)"
        if advisory.confidence.hardware_revision.value == "database-inference"
        else ""
    )
    console.print(
        f"  Hardware revision:   {advisory.hardware_revision or 'unknown'}{revision_suffix}"
    )
    mcu_suffix = (
        " (user supplied)"
        if advisory.confidence.mcu_family.value == "user-supplied"
        else " (catalog inference)"
        if advisory.confidence.mcu_family.value == "database-inference"
        else ""
    )
    console.print(f"  MCU:                 {advisory.mcu or 'unknown'}{mcu_suffix}")
    console.print("\n  [bold]Confidence[/bold]")
    confidence_rows = (
        ("Transport", advisory.confidence.serial_transport),
        ("Protocol", advisory.confidence.protocol_family),
        ("Firmware version", advisory.confidence.firmware_version),
        ("Model", advisory.confidence.radio_model),
        ("Hardware revision", advisory.confidence.hardware_revision),
        ("MCU family", advisory.confidence.mcu_family),
        ("FW compatibility", advisory.confidence.firmware_compatibility),
    )
    for label, confidence in confidence_rows:
        console.print(f"    {label + ':':<20}{confidence.value}")
    for entry in advisory.entries:
        console.print(f"\n  [bold]{entry.name}[/bold]")
        console.print(f"    Compatibility:     {entry.compatibility.value}")
        for reason in entry.reasons:
            console.print(f"    Reason:            {reason}")
    console.print("\n  [bold]Action required[/bold]")
    console.print(
        "    Inspect the label and PCB/revision marking under the battery or provide an "
        "independently verified MCU/revision before selecting firmware."
    )
    console.print("\n  [bold]Safety[/bold]")
    for warning in advisory.warnings:
        console.print(f"    {warning}")


@app.command("ports")
def ports_command() -> None:
    ports = list_serial_ports()
    if not ports:
        console.print("[yellow]No serial ports found.[/yellow]")
        raise typer.Exit(1)
    table = Table(title="Serial ports")
    for column in ("Device", "Description", "VID:PID", "Manufacturer"):
        table.add_column(column)
    for port in ports:
        table.add_row(
            port.device, port.description or "-", port.vid_pid or "-", port.manufacturer or "-"
        )
    console.print(table)


@app.command("drivers")
def drivers_command(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    if as_json:
        sys.stdout.write(
            json.dumps(
                {
                    "drivers": [
                        {
                            "api_version": driver.info.api_version,
                            "driver_id": driver.info.id,
                            "driver_version": driver.info.version,
                            "protocols": list(driver.info.protocols),
                            "safety": driver.info.safety,
                        }
                        for driver in drivers()
                    ]
                },
                sort_keys=True,
            )
            + "\n"
        )
        return
    table = Table(title="Built-in radio drivers")
    for column in ("ID", "Version", "Protocols", "Safety"):
        table.add_column(column)
    for driver in drivers():
        table.add_row(
            driver.info.id,
            driver.info.version,
            ", ".join(driver.supported_protocols()),
            driver.info.safety,
        )
    console.print(table)


@app.command("driver-info")
def driver_info_command(
    driver_id: str, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    try:
        driver = get_driver(driver_id)
    except KeyError as exc:
        error_console.print(str(exc))
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(
            json.dumps(
                {
                    "api_version": driver.info.api_version,
                    "commands": [command.name for command in driver.supported_commands()],
                    "driver_id": driver.info.id,
                    "driver_version": driver.info.version,
                    "models": list(driver.supported_models()),
                    "protocols": list(driver.supported_protocols()),
                    "safety": driver.info.safety,
                },
                sort_keys=True,
            )
            + "\n"
        )
        return
    console.print("[bold]Driver[/bold]")
    console.print(f"  ID:         {driver.info.id}")
    console.print(f"  Version:    {driver.info.version}")
    console.print("[bold]Protocols[/bold]")
    for protocol in driver.supported_protocols():
        console.print(f"  {protocol}")
    console.print("[bold]Models[/bold]")
    for model in driver.supported_models():
        console.print(f"  {model}")
    console.print("[bold]Commands[/bold]")
    for command in driver.supported_commands():
        console.print(f"  {command.name} ({command.safety.value})")
    console.print("[bold]Safety[/bold]")
    console.print(f"  {driver.info.safety}")


def _print_result(result: ProbeResult, *, trace: bool) -> None:
    report = result.report
    frame = result.decoded.frame
    console.print(f"[bold]QSIdentify {__version__}[/bold]")
    console.print("\n[bold]Transport[/bold]")
    console.print(f"  Port:              {report.port.device}")
    console.print(f"  VID:PID:           {report.port.vid_pid or '-'}")
    console.print(f"  Baud rate:         {report.baud_rate}")
    console.print(f"  Request bytes:     {len(result.exchange.transmitted_frame)}")
    console.print(f"  Response bytes:    {len(result.exchange.response)}")
    console.print(f"  Classification:    {report.transport_classification.value}")
    console.print(
        f"  DTR / RTS:         {result.exchange.line_state.dtr} / {result.exchange.line_state.rts}"
    )
    console.print("\n[bold]Protocol[/bold]")
    console.print(f"  Frame detected:    {_yes_no(report.frame_detected)}")
    console.print(f"  Frame complete:    {_yes_no(report.frame_complete)}")
    console.print(f"  Checksum:          {frame.checksum_status.value if frame else '-'}")
    console.print(f"  Message type:      {report.message_type.value}")
    console.print("\n[bold]Radio[/bold]")
    console.print(f"  Operating mode:    {report.operating_mode}")
    console.print(f"  Reported version:  {report.reported_version or '-'}")
    console.print(f"  Bootloader version:{report.reported_bootloader_version or '-':>3}")
    console.print(f"  Detected protocol: {report.detected_protocol or '-'}")
    console.print(f"  Inferred family:   {report.inferred_family or '-'}")
    console.print(f"  Confidence:        {report.confidence.value}")
    if trace:
        console.print("\n[bold]Trace[/bold]")
        console.print(f"  Logical TX payload:   {result.exchange.logical_request.hex(' ')}")
        console.print(f"  Encoded TX frame:     {result.exchange.transmitted_frame.hex(' ')}")
        console.print("  Serial reads")
        for chunk in result.exchange.chunks:
            console.print(
                f"    #{chunk.sequence:<3} +{chunk.monotonic_offset_ms:.3f} ms  "
                f"{len(chunk.data):>4} bytes  {chunk.data.hex(' ')}"
            )
        analysis = result.exchange.analysis
        console.print(f"  Combined raw RX:      {result.exchange.response.hex(' ') or '-'}")
        console.print(f"  Leading bytes:        {analysis.leading_bytes.hex(' ') or '-'}")
        console.print(f"  Detected TX echoes:   {len(analysis.echo_frames)}")
        console.print(f"  Candidate frames:     {len(analysis.candidates)}")
        console.print(f"  Unparsed bytes:       {analysis.unparsed_bytes.hex(' ') or '-'}")
        console.print(f"  Decoded RX payload:   {frame.payload.hex(' ') if frame else '-'}")
        received = (
            f"{frame.checksum_received:04x}"
            if frame is not None and frame.checksum_received is not None
            else "ff ff (legacy marker)"
            if frame is not None
            else "-"
        )
        calculated = f"{frame.checksum_calculated:04x}" if frame else "-"
        console.print(f"  Checksum received:    {received}")
        console.print(f"  Checksum calculated:  {calculated}")
    for warning in report.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


@app.command("probe")
def probe_command(
    device: Annotated[str | None, typer.Argument()] = None,
    auto: Annotated[bool, typer.Option("--auto")] = False,
    baud_rate: Annotated[int, typer.Option("--baud", min=1)] = 38400,
    timeout: Annotated[float, typer.Option("--timeout", min=0.01)] = 3.0,
    idle_timeout: Annotated[float, typer.Option("--idle-timeout", min=0.001)] = 0.2,
    settle_delay: Annotated[float, typer.Option("--settle-delay", min=0.0)] = 0.1,
    dtr: Annotated[LineSetting, typer.Option("--dtr")] = LineSetting.AUTO,
    rts: Annotated[LineSetting, typer.Option("--rts")] = LineSetting.AUTO,
    trace: Annotated[bool, typer.Option("--trace")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    capture_path: Annotated[Path | None, typer.Option("--capture")] = None,
    firmware_advice: Annotated[bool, typer.Option("--firmware-advice")] = False,
    model: Annotated[str | None, typer.Option("--model")] = None,
    hardware_revision: Annotated[str | None, typer.Option("--hardware-revision")] = None,
    mcu: Annotated[str | None, typer.Option("--mcu")] = None,
    pcb_marking: Annotated[str | None, typer.Option("--pcb-marking")] = None,
    driver_id: Annotated[str, typer.Option("--driver")] = "quansheng",
) -> None:
    if auto and device:
        raise typer.BadParameter("Use either a device argument or --auto, not both.")
    if not auto and not device:
        raise typer.BadParameter("Specify a serial device or use --auto.")
    try:
        port = choose_auto_port() if auto else find_port(device or "")
        driver = get_driver(driver_id)
        result = probe_port(
            port,
            driver=driver,
            baud_rate=baud_rate,
            timeout=timeout,
            idle_timeout=idle_timeout,
            settle_delay=settle_delay,
            dtr=dtr,
            rts=rts,
        )
        if capture_path is not None:
            write_capture(capture_path, build_capture(result))
    except (KeyError, RuntimeError, TransportError, OSError) as exc:
        error_console.print(f"Probe failed: {exc}")
        raise typer.Exit(2) from None
    supplied = _hardware_input(model, hardware_revision, mcu, pcb_marking)
    try:
        advisory = (
            _firmware_advisory(build_capture(result), supplied)
            if firmware_advice or any((model, hardware_revision, mcu, pcb_marking))
            else None
        )
    except ValueError as exc:
        error_console.print(f"Firmware advice failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        output = result.report.to_dict()
        if advisory is not None:
            output["firmware_advisory"] = advisory.to_dict()
        sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
    else:
        if capture_path is not None:
            console.print(f"Capture: {capture_path}")
        _print_result(result, trace=trace)
        if advisory is not None:
            _print_advisory(advisory)
    if advisory is not None and advisory.conflicting:
        raise typer.Exit(2)
    if result.report.message_type is MessageType.NO_RESPONSE:
        raise typer.Exit(1)
    if result.report.message_type in {
        MessageType.INCOMPLETE_RESPONSE,
        MessageType.INVALID_FRAME,
    }:
        raise typer.Exit(2)
    if result.report.message_type in {
        MessageType.VALID_UNKNOWN_FRAME,
        MessageType.UNKNOWN_SERIAL_RESPONSE,
        MessageType.TRANSMIT_ECHO,
        MessageType.ECHO_ONLY,
        MessageType.PARTIAL_TRANSMIT_ECHO,
        MessageType.NULL_BYTE_RESPONSE,
        MessageType.UNFRAMED_BINARY_RESPONSE,
    }:
        raise typer.Exit(1)


@app.command("monitor")
def monitor_command(
    device: str,
    duration: Annotated[float, typer.Option("--duration", min=0.01)] = 5.0,
    idle_timeout: Annotated[float, typer.Option("--idle-timeout", min=0.001)] = 1.0,
    baud_rate: Annotated[int, typer.Option("--baud", min=1)] = 38400,
    dtr: Annotated[LineSetting, typer.Option("--dtr")] = LineSetting.AUTO,
    rts: Annotated[LineSetting, typer.Option("--rts")] = LineSetting.AUTO,
    trace: Annotated[bool, typer.Option("--trace")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    capture_path: Annotated[Path | None, typer.Option("--capture")] = None,
    driver_id: Annotated[str, typer.Option("--driver")] = "quansheng",
) -> None:
    try:
        result = monitor_port(
            find_port(device),
            driver=get_driver(driver_id),
            baud_rate=baud_rate,
            duration=duration,
            idle_timeout=idle_timeout,
            dtr=dtr,
            rts=rts,
        )
        if capture_path is not None:
            write_capture(capture_path, build_capture(result))
    except (KeyError, RuntimeError, TransportError, OSError, ValueError) as exc:
        error_console.print(f"Monitor failed: {exc}")
        raise typer.Exit(2) from None
    if as_json:
        sys.stdout.write(json.dumps(result.report.to_dict(), sort_keys=True) + "\n")
    else:
        _print_result(result, trace=trace)
    if result.report.message_type is MessageType.NO_RESPONSE:
        raise typer.Exit(1)


@app.command("matrix")
def matrix_command(
    device: str,
    settle_delays: Annotated[list[float] | None, typer.Option("--settle-delay")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.01)] = 3.0,
    idle_timeout: Annotated[float, typer.Option("--idle-timeout", min=0.001)] = 0.2,
    pause: Annotated[float, typer.Option("--pause", min=0.0)] = 0.25,
    capture_dir: Annotated[Path | None, typer.Option("--capture-dir")] = None,
    driver_id: Annotated[str, typer.Option("--driver")] = "quansheng",
) -> None:
    delays = settle_delays or [0.1]
    if len(delays) > 3 or any(value < 0 for value in delays):
        raise typer.BadParameter("Use at most three non-negative settle delays.")
    states = (
        (LineSetting.OFF, LineSetting.OFF),
        (LineSetting.ON, LineSetting.OFF),
        (LineSetting.OFF, LineSetting.ON),
        (LineSetting.ON, LineSetting.ON),
    )
    port = find_port(device)
    try:
        driver = get_driver(driver_id)
    except KeyError as exc:
        error_console.print(f"Matrix failed: {exc}")
        raise typer.Exit(2) from None
    attempt = 0
    for delay in delays:
        for dtr, rts in states:
            attempt += 1
            try:
                result = probe_port(
                    port,
                    driver=driver,
                    timeout=timeout,
                    idle_timeout=idle_timeout,
                    settle_delay=delay,
                    dtr=dtr,
                    rts=rts,
                )
            except (RuntimeError, TransportError, OSError, ValueError) as exc:
                error_console.print(f"Matrix attempt {attempt} failed: {exc}")
                raise typer.Exit(2) from None
            console.print(
                f"#{attempt}: DTR {dtr.value}, RTS {rts.value}, settle {delay:g}s: "
                f"{result.report.transport_classification.value}"
            )
            if capture_dir is not None:
                name = f"attempt-{attempt:02d}-dtr-{dtr.value}-rts-{rts.value}.json"
                write_capture(capture_dir / name, build_capture(result))
            if pause:
                time.sleep(pause)


def _print_decoded(decoded: DecodedResponse) -> None:
    console.print(f"Message type:      {decoded.message_type.value}")
    console.print(f"Reported version:  {decoded.reported_version or '-'}")
    console.print(f"Bootloader version:{decoded.reported_bootloader_version or '-':>3}")
    console.print(f"Detected protocol: {decoded.detected_protocol or '-'}")
    console.print(f"Inferred family:   {decoded.inferred_family or '-'}")
    console.print(f"Confidence:        {decoded.confidence.value}")


@app.command("decode")
def decode_command(path: Path) -> None:
    try:
        capture = read_capture(path)
    except CaptureError as exc:
        error_console.print(f"Invalid capture: {exc}")
        raise typer.Exit(3) from None
    console.print(f"QSIdentify {__version__}")
    console.print(f"Capture:           {path}")
    console.print(f"Created:           {capture.created_utc}")
    console.print(f"Port:              {capture.port.device}")
    _print_decoded(
        DecodedResponse(
            capture.report.reported_version,
            capture.report.reported_bootloader_version,
            capture.report.detected_protocol,
            capture.report.message_type,
            capture.report.inferred_family,
            capture.report.confidence,
            capture.report.evidence,
            capture.report.warnings,
        )
    )
    console.print(f"Response bytes:    {len(bytes.fromhex(capture.raw_response_hex))}")


@app.command("compare")
def compare_command(
    paths: Annotated[list[Path], typer.Argument()],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        captures = tuple(read_capture(path) for path in paths)
        comparison = compare_captures(captures)
    except (CaptureError, ValueError) as exc:
        error_console.print(f"Compare failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(
            json.dumps(
                {
                    "byte_frequency": [list(item) for item in comparison.byte_frequency],
                    "common_positions": [list(item) for item in comparison.common_positions],
                    "common_prefix_hex": comparison.common_prefix.hex(),
                    "common_suffix_hex": comparison.common_suffix.hex(),
                    "exact_match": comparison.exact_match,
                    "summaries": [
                        {
                            "classification": item.classification,
                            "echo_present": item.echo_present,
                            "framed": item.framed,
                            "null_percentage": item.null_percentage,
                            "response_length": item.response_length,
                            "sha256": item.sha256,
                        }
                        for item in comparison.summaries
                    ],
                },
                sort_keys=True,
            )
            + "\n"
        )
        return
    table = Table(title="Capture comparison")
    for column in (
        "Capture",
        "Bytes",
        "Classification",
        "Framed",
        "Echo",
        "Null %",
        "SHA-256",
    ):
        table.add_column(column)
    for path, summary in zip(paths, comparison.summaries, strict=True):
        table.add_row(
            str(path),
            str(summary.response_length),
            summary.classification,
            _yes_no(summary.framed),
            _yes_no(summary.echo_present),
            f"{summary.null_percentage:.1f}",
            summary.sha256,
        )
    console.print(table)
    console.print(f"Exact match:       {_yes_no(comparison.exact_match)}")
    console.print(f"Common prefix:     {comparison.common_prefix.hex(' ') or '-'}")
    console.print(f"Common suffix:     {comparison.common_suffix.hex(' ') or '-'}")
    console.print(f"Common positions:  {len(comparison.common_positions)}")
    frequency = " ".join(f"{value:02x}:{count}" for value, count in comparison.byte_frequency)
    console.print(f"Byte frequency:    {frequency or '-'}")


@app.command("firmware-advice")
def firmware_advice_command(
    path: Path,
    model: Annotated[str | None, typer.Option("--model")] = None,
    hardware_revision: Annotated[str | None, typer.Option("--hardware-revision")] = None,
    mcu: Annotated[str | None, typer.Option("--mcu")] = None,
    pcb_marking: Annotated[str | None, typer.Option("--pcb-marking")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        capture = read_capture(path)
        advisory = _firmware_advisory(
            capture, _hardware_input(model, hardware_revision, mcu, pcb_marking)
        )
    except (CaptureError, ValueError) as exc:
        error_console.print(f"Firmware advice failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(
            json.dumps({"firmware_advisory": advisory.to_dict()}, sort_keys=True) + "\n"
        )
    else:
        _print_advisory(advisory)
    if advisory.conflicting:
        raise typer.Exit(2)


@app.command("firmware-list")
def firmware_list_command() -> None:
    try:
        driver = default_driver()
        entries = driver.firmware_projects()
    except ValueError as exc:
        error_console.print(f"Firmware catalog failed: {exc}")
        raise typer.Exit(3) from None
    table = Table(title=f"Firmware catalog ({driver.info.id})")
    for column in ("ID", "Supported MCU", "Status", "Project"):
        table.add_column(column)
    for entry in entries:
        table.add_row(entry.id, ", ".join(entry.supported_mcus), entry.status, entry.project)
    console.print(table)


@app.command("hardware-list")
def hardware_list_command() -> None:
    try:
        records = default_driver().hardware_records()
    except ValueError as exc:
        error_console.print(f"Hardware catalog failed: {exc}")
        raise typer.Exit(3) from None
    table = Table(title="Known hardware records")
    for column in ("ID", "Revision", "MCU", "Evidence required"):
        table.add_column(column)
    for record in records:
        table.add_row(
            record.id,
            record.revision,
            record.mcu,
            "; ".join(record.evidence_requirements),
        )
    console.print(table)


@app.command("firmware-catalog-validate")
def firmware_catalog_validate_command() -> None:
    try:
        validation = default_driver().validate_catalog()
    except ValueError as exc:
        error_console.print(f"Firmware catalog invalid: {exc}")
        raise typer.Exit(3) from None
    console.print(
        f"Firmware catalog {validation.version} is valid: "
        f"{validation.firmware_entries} entries, "
        f"{validation.hardware_records} hardware records."
    )


@app.command("capture-sanitize")
def capture_sanitize_command(
    input_path: Path,
    output_path: Path,
    verify: Annotated[bool, typer.Option("--verify")] = True,
) -> None:
    if input_path.resolve() == output_path.resolve():
        error_console.print("Capture sanitize refused: input and output must differ.")
        raise typer.Exit(3)
    try:
        capture = read_capture(input_path)
        sanitized, transformations = sanitize_capture(capture)
        write_capture(output_path, sanitized)
        if verify and validate_capture(output_path).status is not ValidationStatus.VALID:
            raise CaptureError("Sanitized capture did not validate cleanly.")
    except (CaptureError, OSError) as exc:
        error_console.print(f"Capture sanitize failed: {exc}")
        raise typer.Exit(3) from None
    for item in transformations:
        console.print(f"Applied: {item}")
    console.print("Sanitized capture written and validated.")


@app.command("capture-inspect")
def capture_inspect_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    try:
        result = inspect_capture(read_capture(path))
    except CaptureError as exc:
        error_console.print(f"Capture inspect failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
        return
    for key, value in result.items():
        console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("capture-validate")
def capture_validate_command(
    paths: Annotated[list[Path], typer.Argument()],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    results = [(path, validate_capture(path)) for path in paths]
    if as_json:
        sys.stdout.write(
            json.dumps({"captures": [result.to_dict() for _, result in results]}, sort_keys=True)
            + "\n"
        )
    else:
        for _path, result in results:
            console.print(result.status.value)
    statuses = {result.status for _, result in results}
    if ValidationStatus.UNKNOWN_DRIVER in statuses:
        raise typer.Exit(5)
    if ValidationStatus.UNSUPPORTED_SCHEMA in statuses:
        raise typer.Exit(4)
    if ValidationStatus.INVALID in statuses:
        raise typer.Exit(3)
    if ValidationStatus.VALID_WARNINGS in statuses:
        raise typer.Exit(1)


@app.command("release-info")
def release_info_command(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    info = release_info()
    if as_json:
        sys.stdout.write(json.dumps(info, sort_keys=True) + "\n")
        return
    for key, value in info.items():
        console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("audit")
def audit_command(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    checks = audit_results()
    if as_json:
        sys.stdout.write(json.dumps({"checks": checks}, sort_keys=True) + "\n")
    else:
        for check in checks:
            console.print(f"{check['check']}: {'ok' if check['ok'] else 'failed'}")
    if not all(check["ok"] for check in checks):
        raise typer.Exit(1)


@app.command("command-list")
def command_list_command(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    commands = load_command_inventory()
    payload = {
        "commands": [
            {
                "allowlisted": item.allowlisted,
                "command_id": item.command_id,
                "evidence_categories": list(item.evidence_categories),
                "read_only": item.read_only,
                "safety_class": item.safety_class,
                "symbolic_name": item.symbolic_name,
            }
            for item in commands
        ]
    }
    if as_json:
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        return
    table = Table("ID", "Name", "Safety", "Allowlisted")
    for item in commands:
        table.add_row(
            item.command_id, item.symbolic_name, item.safety_class, _yes_no(item.allowlisted)
        )
    console.print(table)


@app.command("command-info")
def command_info_command(
    command_id: str,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    command = next(
        (
            item
            for item in load_command_inventory()
            if item.command_id == command_id or item.symbolic_name == command_id
        ),
        None,
    )
    if command is None:
        error_console.print(f"Unknown command inventory ID: {command_id}")
        raise typer.Exit(2)
    payload = {
        "allowlisted": command.allowlisted,
        "command_id": command.command_id,
        "evidence_categories": list(command.evidence_categories),
        "expected_response_lengths": list(command.expected_response_lengths),
        "minimum_request": command.minimum_request,
        "notes": list(command.notes),
        "provenance": list(command.provenance),
        "read_only": command.read_only,
        "request_type": command.request_type,
        "response_type": command.response_type,
        "safety_class": command.safety_class,
        "symbolic_name": command.symbolic_name,
    }
    if as_json:
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    else:
        for key, value in payload.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")


def _read_capture_set(paths: list[Path]) -> tuple[Capture, ...]:
    if not paths:
        raise typer.BadParameter("At least one capture is required.")
    try:
        return tuple(read_capture(path) for path in paths)
    except (CaptureError, OSError) as exc:
        error_console.print(f"Evidence input failed: {exc}")
        raise typer.Exit(3) from None


@app.command("evidence-report")
def evidence_report_command(
    paths: list[Path],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        report = evidence_report(_read_capture_set(paths))
    except EvidenceError as exc:
        error_console.print(f"Evidence analysis failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
        return
    fingerprint = report["fingerprint"]
    observed = report["observed"]
    console.print("[bold]Electronic evidence[/bold]")
    console.print(f"  Firmware:          {', '.join(observed['firmware_strings']) or 'unresolved'}")
    console.print(f"  Stable bytes:      {len(observed['stable_positions'])}")
    console.print(f"  Variable bytes:    {len(observed['variable_positions'])}")
    console.print(f"  Fingerprint:       {fingerprint['fingerprint_id']}")
    console.print("[bold]Unresolved[/bold]")
    console.print(f"  {', '.join(report['unresolved'])}")


@app.command("evidence-compare")
def evidence_compare_command(
    paths: list[Path],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        comparison = compare_evidence(_read_capture_set(paths))
    except EvidenceError as exc:
        error_console.print(f"Evidence comparison failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(json.dumps(comparison, sort_keys=True) + "\n")
        return
    for key, value in comparison.items():
        console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("evidence-export")
def evidence_export_command(
    paths: list[Path],
    output: Annotated[Path, typer.Option("--output", "-o")],
    provenance_notes: Annotated[str, typer.Option("--provenance-notes")] = "",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        bundle = export_bundle(tuple(paths), output, provenance_notes)
    except (CaptureError, EvidenceError, OSError) as exc:
        error_console.print(f"Evidence export failed: {exc}")
        raise typer.Exit(3) from None
    result = {"capture_count": len(bundle["captures"]), "output": output.name, "status": "valid"}
    if as_json:
        sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    else:
        console.print(
            f"Evidence bundle written: {output.name} ({result['capture_count']} captures)"
        )


@app.command("evidence-bundle-inspect")
def evidence_bundle_inspect_command(
    bundle: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        result = inspect_bundle(bundle)
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        error_console.print(f"Bundle inspection failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    else:
        for key, value in result.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("evidence-bundle-validate")
def evidence_bundle_validate_command(
    bundle: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    ok, errors = validate_bundle(bundle)
    result = {"errors": list(errors), "status": "valid" if ok else "invalid"}
    if as_json:
        sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    else:
        console.print(result["status"])
        for error in errors:
            error_console.print(error)
    if not ok:
        raise typer.Exit(3)


@app.command("evidence-probe")
def evidence_probe_command(
    device: str,
    probe_id: Annotated[str, typer.Option("--probe")] = "firmware-identification",
    repeat: Annotated[int | None, typer.Option("--repeat", min=1, max=20)] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.01)] = 3.0,
    capture_directory: Annotated[Path | None, typer.Option("--capture-directory")] = None,
    trace: Annotated[bool, typer.Option("--trace")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    device_alias: Annotated[str | None, typer.Option("--device-alias")] = None,
    marketed_model: Annotated[str | None, typer.Option("--marketed-model")] = None,
    production_sticker: Annotated[str | None, typer.Option("--production-sticker")] = None,
    boot_screen_text: Annotated[str | None, typer.Option("--boot-screen-text")] = None,
    menu_range: Annotated[str | None, typer.Option("--menu-range")] = None,
    revision_marking: Annotated[str | None, typer.Option("--revision-marking")] = None,
    physical_device_group: Annotated[str | None, typer.Option("--physical-device-group")] = None,
    experiment_id: Annotated[str | None, typer.Option("--experiment-id")] = None,
) -> None:
    definitions = {item.id: item for item in load_probe_definitions()}
    definition = definitions.get(probe_id)
    if definition is None or not definition.available:
        error_console.print(f"Unavailable or unknown evidence probe: {probe_id}")
        raise typer.Exit(2)
    count = repeat if repeat is not None else definition.repeat_count
    plan = {
        "commands": list(definition.commands),
        "driver_id": definition.driver_id,
        "evidence_targets": list(definition.evidence_targets),
        "experimental": definition.experimental,
        "probe_id": definition.id,
        "repeat_count": count,
        "safety": "passive" if not definition.commands else "identification-read",
    }
    captures: list[Capture] = []
    labels = {
        key: value
        for key, value in {
            "boot_screen_text": boot_screen_text,
            "device_alias": device_alias,
            "experiment_id": experiment_id,
            "marketed_model": marketed_model,
            "menu_range": menu_range,
            "physical_device_group": physical_device_group,
            "production_sticker": production_sticker,
            "user_observed_revision_marking": revision_marking,
        }.items()
        if value is not None
    }
    try:
        port = find_port(device)
        for index in range(count):
            result = (
                monitor_port(port, duration=timeout)
                if not definition.commands
                else probe_port(port, timeout=timeout)
            )
            capture = build_capture(result)
            if labels:
                capture = replace(capture, capture_metadata=labels)
            captures.append(capture)
            if capture_directory is not None:
                write_capture(capture_directory / f"{definition.id}-{index + 1:02}.json", capture)
            if trace and not as_json:
                _print_result(result, trace=True)
    except (RuntimeError, TransportError, OSError) as exc:
        error_console.print(f"Evidence probe failed: {exc}")
        raise typer.Exit(2) from None
    output = {"plan": plan, "report": evidence_report(tuple(captures))}
    if as_json:
        sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
    elif not trace:
        console.print(f"Probe: {definition.name}; captures: {len(captures)}")


@app.command("identify")
def identify_command(
    device: str,
    model: Annotated[str | None, typer.Option("--model")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.01)] = 3.0,
    repeat: Annotated[int, typer.Option("--repeat", min=1, max=20)] = 1,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Collect identity evidence using only the allowlisted identification read."""
    captures: list[Capture] = []
    try:
        port = find_port(device)
        for _ in range(repeat):
            capture = build_capture(probe_port(port, timeout=timeout))
            if model is not None:
                capture = replace(capture, capture_metadata={"marketed_model": model})
            captures.append(capture)
    except (RuntimeError, TransportError, OSError) as exc:
        error_console.print(f"Identification failed: {exc}")
        raise typer.Exit(2) from None
    report = evidence_report(tuple(captures))
    if as_json:
        sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
        return
    observed = report["observed"]
    labels = report["user_supplied_labels"]
    confidence = report["confidence"]
    console.print("[bold]Electronic identity[/bold]")
    console.print("  Manufacturer:       Quansheng")
    console.print("  Protocol family:    UV-K5 protocol")
    console.print(
        f"  Firmware:           {', '.join(observed['firmware_strings']) or 'unresolved'}"
    )
    model_text = labels.get("marketed_model", "unresolved")
    if "marketed_model" in labels:
        model_text += " (user supplied)"
    console.print(f"  Marketed model:     {model_text}")
    console.print("  Hardware revision:  unresolved")
    console.print("  MCU:                unresolved")
    console.print("  PCB revision:       unresolved")
    console.print("  Bootloader:         unresolved")
    console.print("[bold]Evidence[/bold]")
    console.print(f"  Protocol:           {confidence['protocol']}")
    console.print(f"  Firmware:           {confidence['firmware']}")
    stability_text = (
        f"confirmed across {repeat} probes" if repeat > 1 else "not assessed (one probe)"
    )
    console.print(f"  Stable response:    {stability_text}")
    console.print("  MCU discriminator:  unavailable")
    console.print("[bold]Fingerprint[/bold]")
    console.print(f"  ID:                 {report['fingerprint']['fingerprint_id']}")
    console.print("[bold]Next required evidence[/bold]")
    console.print("  A verified electronic discriminator for hardware revision or MCU.")


def _registry_output(value: object, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")


@app.command("registry-create")
def registry_create_command(
    path: Path,
    label: Annotated[str, typer.Option("--label")] = "default",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if path.exists():
        error_console.print("Registry already exists; refusing to overwrite it.")
        raise typer.Exit(2)
    try:
        registry = create_registry(registry_label=label)
        write_registry(path, registry)
    except (RegistryError, OSError) as exc:
        error_console.print(f"Registry creation failed: {exc}")
        raise typer.Exit(3) from None
    output = {
        "registry_digest": registry.registry_digest,
        "registry_id": registry.registry_id,
        "schema_version": registry.schema_version,
        "status": "created",
    }
    if as_json:
        _registry_output(output, True)
    else:
        console.print(f"Registry created: {registry.registry_id}")


@app.command("registry-info")
def registry_info_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    try:
        registry = load_registry(path)
        analysis = analyze_registry(registry)
    except RegistryError as exc:
        error_console.print(f"Registry inspection failed: {exc}")
        raise typer.Exit(3) from None
    output = {
        **analysis,
        "conflicts": [item.to_dict() for item in detect_conflicts(registry)],
        "registry_digest": registry.registry_digest,
        "registry_id": registry.registry_id,
        "schema_version": registry.schema_version,
    }
    if as_json:
        _registry_output(output, True)
    else:
        for key, value in output.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("registry-validate")
def registry_validate_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    try:
        registry = load_registry(path)
        result = validate_registry(registry)
    except RegistryError as exc:
        result = None
        message = str(exc)
    else:
        message = ""
    output: dict[str, Any] = (
        result.to_dict()
        if result is not None
        else {"errors": [message], "valid": False, "warnings": []}
    )
    if as_json:
        _registry_output(output, True)
    else:
        console.print("valid" if output["valid"] else "invalid")
        for error in output["errors"]:
            error_console.print(error)
    if not output["valid"]:
        raise typer.Exit(3)


@app.command("registry-add")
def registry_add_command(
    registry_path: Path,
    bundles: list[Path],
    device_label: Annotated[str | None, typer.Option("--device-label")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        registry = load_registry(registry_path)
        imported: list[str] = []
        relationships: list[str] = []
        conflicts: list[dict[str, Any]] = []
        for bundle in bundles:
            mutation = add_evidence_bundle(registry, bundle, device_label=device_label)
            registry = mutation.registry
            imported.extend(mutation.imported_bundle_ids)
            relationships.extend(mutation.relationships)
            conflicts.extend(item.to_dict() for item in mutation.conflicts)
        write_registry(registry_path, registry)
    except DuplicateEvidenceError as exc:
        error_console.print(str(exc))
        raise typer.Exit(1) from None
    except (RegistryError, OSError) as exc:
        error_console.print(f"Registry add failed: {exc}")
        raise typer.Exit(3) from None
    output = {
        "conflicts": conflicts,
        "imported_bundle_ids": sorted(imported),
        "relationships": sorted(set(relationships)),
    }
    if as_json:
        _registry_output(output, True)
    else:
        console.print(f"Imported {len(imported)} bundle(s).")


@app.command("registry-remove")
def registry_remove_command(
    registry_path: Path,
    bundle_id: str,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        registry = remove_evidence_bundle(load_registry(registry_path), bundle_id)
        write_registry(registry_path, registry)
    except (RegistryError, OSError) as exc:
        error_console.print(f"Registry removal failed: {exc}")
        raise typer.Exit(3) from None
    output = {"bundle_id": bundle_id, "status": "removed"}
    if as_json:
        _registry_output(output, True)
    else:
        console.print(f"Removed {bundle_id}; audit event retained.")


@app.command("registry-list")
def registry_list_command(
    registry_path: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        registry = load_registry(registry_path)
    except RegistryError as exc:
        error_console.print(f"Registry listing failed: {exc}")
        raise typer.Exit(3) from None
    output = {
        "bundles": [
            {
                "bundle_id": item.bundle_id,
                "content_digest": item.content_digest,
                "device_id": item.device_id,
                "electronic_fingerprint": item.electronic_fingerprint,
            }
            for item in registry.bundles
        ]
    }
    if as_json:
        _registry_output(output, True)
    else:
        table = Table("Bundle ID", "Device", "Fingerprint")
        for item in output["bundles"]:
            table.add_row(
                item["bundle_id"], item["device_id"] or "unknown", item["electronic_fingerprint"]
            )
        console.print(table)


@app.command("registry-export")
def registry_export_command(
    registry_path: Path,
    output: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if registry_path.resolve() == output.resolve():
        error_console.print("Registry export output must differ from its input.")
        raise typer.Exit(2)
    try:
        registry = load_registry(registry_path)
        write_registry(output, registry)
    except (RegistryError, OSError) as exc:
        error_console.print(f"Registry export failed: {exc}")
        raise typer.Exit(3) from None
    result = {"registry_digest": registry.registry_digest, "status": "exported"}
    if as_json:
        _registry_output(result, True)
    else:
        console.print("Registry exported.")


@app.command("registry-matrix")
def registry_matrix_command(
    registry_path: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        rows = registry_matrix(load_registry(registry_path))
    except RegistryError as exc:
        error_console.print(f"Registry matrix failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        _registry_output({"devices": list(rows)}, True)
        return
    table = Table("Device", "Firmware", "Fingerprint", "Declared MCU", "Declared PCB")
    for row in rows:
        table.add_row(
            row["label"],
            ", ".join(row["firmware"]) or "unknown",
            ", ".join(row["fingerprints"]) or "unknown",
            row["declared_mcu"] or "unknown",
            row["declared_pcb"] or "unknown",
        )
    console.print(table)


@app.command("registry-discriminators")
def registry_discriminators_command(
    registry_path: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        candidates = load_registry(registry_path).candidates
    except RegistryError as exc:
        error_console.print(f"Candidate listing failed: {exc}")
        raise typer.Exit(3) from None
    output = {"candidates": [{**asdict(item), "status": item.status.value} for item in candidates]}
    if as_json:
        _registry_output(output, True)
    else:
        for item in output["candidates"]:
            console.print(f"{item['candidate_id']}: {item['status']}")


@app.command("registry-discriminator-show")
def registry_discriminator_show_command(
    registry_path: Path,
    candidate_id: str,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        candidate = next(
            (
                item
                for item in load_registry(registry_path).candidates
                if item.candidate_id == candidate_id
            ),
            None,
        )
    except RegistryError as exc:
        error_console.print(f"Candidate inspection failed: {exc}")
        raise typer.Exit(3) from None
    if candidate is None:
        error_console.print(f"Unknown candidate: {candidate_id}")
        raise typer.Exit(2)
    output = {**asdict(candidate), "status": candidate.status.value}
    if as_json:
        _registry_output(output, True)
    else:
        for key, value in output.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")


@app.command("registry-discriminator-propose")
def registry_discriminator_propose_command(
    registry_path: Path,
    offset: Annotated[int, typer.Option("--offset", min=0)],
    length: Annotated[int, typer.Option("--length", min=1, max=32)],
    scope: Annotated[str, typer.Option("--scope")] = "quansheng",
    probe: Annotated[str, typer.Option("--probe")] = "firmware-identification",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        registry = propose_discriminator(
            load_registry(registry_path),
            offset=offset,
            length=length,
            driver_id=scope,
            probe_definition=probe,
        )
        write_registry(registry_path, registry)
        candidate = next(
            item for item in registry.candidates if item.offset == offset and item.length == length
        )
    except (RegistryError, OSError) as exc:
        error_console.print(f"Candidate proposal failed: {exc}")
        raise typer.Exit(3) from None
    output = {**asdict(candidate), "status": candidate.status.value}
    if as_json:
        _registry_output(output, True)
    else:
        console.print(f"{candidate.candidate_id}: {candidate.status.value}")


@app.command("registry-catalog-proposal")
def registry_catalog_proposal_command(
    registry_path: Path,
    output: Path,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        proposal = catalog_proposal(load_registry(registry_path))
        if proposal["blocking_conflicts"]:
            error_console.print("Catalog proposal blocked by registry conflicts.")
            raise typer.Exit(2)
        write_json_atomic(output, proposal)
    except (RegistryError, OSError) as exc:
        error_console.print(f"Catalog proposal failed: {exc}")
        raise typer.Exit(3) from None
    result = {
        "blocking_conflict_count": len(proposal["blocking_conflicts"]),
        "candidate_count": len(proposal["candidates"]),
        "status": "manual-review-required",
    }
    if as_json:
        _registry_output(result, True)
    else:
        console.print("Catalog proposal written; manual review is required.")


@app.command("contribution-create")
def contribution_create_command(
    bundles: list[Path],
    output: Annotated[Path, typer.Option("--output", "-o")],
    notes: Annotated[str, typer.Option("--notes")] = "",
    declarations_path: Annotated[Path | None, typer.Option("--declarations")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        declarations: tuple[dict[str, Any], ...] = ()
        if declarations_path is not None:
            raw_declarations = json.loads(declarations_path.read_text(encoding="utf-8"))
            if not isinstance(raw_declarations, list) or not all(
                isinstance(item, dict) for item in raw_declarations
            ):
                raise ContributionError("Declarations file must be a JSON array of objects.")
            declarations = tuple(raw_declarations)
        contribution_id = create_contribution(
            tuple(bundles), output, declarations=declarations, notes=notes
        )
    except (ContributionError, OSError, json.JSONDecodeError) as exc:
        error_console.print(f"Contribution creation failed: {exc}")
        raise typer.Exit(3) from None
    result = {"bundle_count": len(bundles), "contribution_id": contribution_id, "status": "created"}
    if as_json:
        _registry_output(result, True)
    else:
        console.print(f"Contribution created: {contribution_id}")


@app.command("contribution-inspect")
def contribution_inspect_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    try:
        result = inspect_contribution(path)
    except (ContributionError, OSError) as exc:
        error_console.print(f"Contribution inspection failed: {exc}")
        raise typer.Exit(3) from None
    if as_json:
        _registry_output(result, True)
    else:
        for key, value in result.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")


def _contribution_review_output(path: Path, as_json: bool) -> None:
    review = review_contribution(path)
    if as_json:
        _registry_output(review.to_dict(), True)
    else:
        console.print(review.classification)
        for warning in review.warnings:
            error_console.print(f"Warning: {warning}")
        for error in review.errors:
            error_console.print(error)
    if not review.safe:
        raise typer.Exit(3)


@app.command("contribution-validate")
def contribution_validate_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    _contribution_review_output(path, as_json)


@app.command("contribution-review")
def contribution_review_command(
    path: Path, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    _contribution_review_output(path, as_json)


@app.command("registry-import-contribution")
def registry_import_contribution_command(
    registry_path: Path,
    contribution_path: Path,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        plan = plan_contribution_import(load_registry(registry_path), contribution_path)
    except (ContributionError, RegistryError, OSError) as exc:
        error_console.print(f"Contribution import failed: {exc}")
        raise typer.Exit(3) from None
    output = {**plan.to_dict(), "dry_run": dry_run, "mutation_performed": False}
    if not dry_run and not yes:
        if as_json:
            _registry_output(output, True)
        error_console.print("Explicit --yes is required before registry mutation.")
        raise typer.Exit(2)
    if not dry_run:
        try:
            write_registry(registry_path, plan.mutation.registry)
        except (RegistryError, OSError) as exc:
            error_console.print(f"Contribution import failed: {exc}")
            raise typer.Exit(3) from None
        output["mutation_performed"] = True
    if as_json:
        _registry_output(output, True)
    else:
        console.print("Import plan complete." if dry_run else "Contribution imported.")


@app.command("fixture-validate")
def fixture_validate_command(
    root: Annotated[Path, typer.Option("--root")] = Path("tests/fixtures"),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = validate_fixture_manifest(root)
    if as_json:
        sys.stdout.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")
    else:
        console.print(f"Fixture corpus: {'valid' if result.ok else 'invalid'} ({result.checked})")
        for error in result.errors:
            error_console.print(error)
    if not result.ok:
        raise typer.Exit(3)


@app.command("doctor")
def doctor_command() -> None:
    failed = False
    table = Table(title="QSIdentify doctor")
    for column in ("Check", "Status", "Mode", "Detail"):
        table.add_column(column)
    for check in run_checks():
        failed = failed or not check.ok
        table.add_row(
            check.name,
            "OK" if check.ok else "WARN",
            "offline" if check.offline else "live",
            check.detail,
        )
    console.print(table)
    if failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
