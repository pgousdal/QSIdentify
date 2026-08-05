from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .advisory import FirmwareAdvisory, HardwareInput, build_advisory
from .capture import CaptureError, build_capture, read_capture, write_capture
from .catalog import CatalogError, load_firmware_catalog, load_hardware_records, validate_catalogs
from .comparison import compare_captures
from .doctor import run_checks
from .models import DecodedResponse, LineSetting, MessageType, ProbeResult
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
) -> HardwareInput:
    return HardwareInput(model, hardware_revision, mcu, pcb_marking)


def _print_advisory(advisory: FirmwareAdvisory) -> None:
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
) -> None:
    if auto and device:
        raise typer.BadParameter("Use either a device argument or --auto, not both.")
    if not auto and not device:
        raise typer.BadParameter("Specify a serial device or use --auto.")
    try:
        port = choose_auto_port() if auto else find_port(device or "")
        result = probe_port(
            port,
            baud_rate=baud_rate,
            timeout=timeout,
            idle_timeout=idle_timeout,
            settle_delay=settle_delay,
            dtr=dtr,
            rts=rts,
        )
        if capture_path is not None:
            write_capture(capture_path, build_capture(result))
    except (RuntimeError, TransportError, OSError) as exc:
        error_console.print(f"Probe failed: {exc}")
        raise typer.Exit(2) from None
    supplied = _hardware_input(model, hardware_revision, mcu, pcb_marking)
    try:
        advisory = (
            build_advisory(build_capture(result), supplied)
            if firmware_advice or any((model, hardware_revision, mcu, pcb_marking))
            else None
        )
    except CatalogError as exc:
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
) -> None:
    try:
        result = monitor_port(
            find_port(device),
            baud_rate=baud_rate,
            duration=duration,
            idle_timeout=idle_timeout,
            dtr=dtr,
            rts=rts,
        )
        if capture_path is not None:
            write_capture(capture_path, build_capture(result))
    except (RuntimeError, TransportError, OSError, ValueError) as exc:
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
    attempt = 0
    for delay in delays:
        for dtr, rts in states:
            attempt += 1
            try:
                result = probe_port(
                    port,
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
def compare_command(paths: Annotated[list[Path], typer.Argument()]) -> None:
    try:
        captures = tuple(read_capture(path) for path in paths)
        comparison = compare_captures(captures)
    except (CaptureError, ValueError) as exc:
        error_console.print(f"Compare failed: {exc}")
        raise typer.Exit(3) from None
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
        advisory = build_advisory(
            capture, _hardware_input(model, hardware_revision, mcu, pcb_marking)
        )
    except (CaptureError, CatalogError) as exc:
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
        catalog = load_firmware_catalog()
    except CatalogError as exc:
        error_console.print(f"Firmware catalog failed: {exc}")
        raise typer.Exit(3) from None
    table = Table(title=f"Firmware catalog {catalog.catalog_version}")
    for column in ("ID", "Supported MCU", "Status", "Project"):
        table.add_column(column)
    for entry in catalog.entries:
        table.add_row(entry.id, ", ".join(entry.supported_mcus), entry.status, entry.project)
    console.print(table)


@app.command("hardware-list")
def hardware_list_command() -> None:
    try:
        records = load_hardware_records()
    except CatalogError as exc:
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
        records, catalog = validate_catalogs()
    except CatalogError as exc:
        error_console.print(f"Firmware catalog invalid: {exc}")
        raise typer.Exit(3) from None
    console.print(
        f"Firmware catalog {catalog.catalog_version} is valid: "
        f"{len(catalog.entries)} entries, {len(records)} hardware records."
    )


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
