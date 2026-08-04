from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .capture import CaptureError, build_capture, read_capture, write_capture
from .doctor import run_checks
from .models import DecodedResponse, MessageType, ProbeResult
from .ports import choose_auto_port, find_port, list_serial_ports
from .probe import probe_port
from .protocol.decoder import decode_response
from .transport import TransportError

app = typer.Typer(
    help="Read-only identification and diagnostics for Quansheng radios.",
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


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
        console.print(f"  Raw RX bytes:         {result.exchange.response.hex(' ') or '-'}")
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
    timeout: Annotated[float, typer.Option("--timeout", min=0.01)] = 1.0,
    trace: Annotated[bool, typer.Option("--trace")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    capture_path: Annotated[Path | None, typer.Option("--capture")] = None,
) -> None:
    if auto and device:
        raise typer.BadParameter("Use either a device argument or --auto, not both.")
    if not auto and not device:
        raise typer.BadParameter("Specify a serial device or use --auto.")
    try:
        port = choose_auto_port() if auto else find_port(device or "")
        result = probe_port(port, baud_rate=baud_rate, timeout=timeout)
        if capture_path is not None:
            write_capture(capture_path, build_capture(result))
    except (RuntimeError, TransportError, OSError) as exc:
        error_console.print(f"Probe failed: {exc}")
        raise typer.Exit(2) from None
    if as_json:
        sys.stdout.write(json.dumps(result.report.to_dict(), sort_keys=True) + "\n")
    else:
        if capture_path is not None:
            console.print(f"Capture: {capture_path}")
        _print_result(result, trace=trace)
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
    }:
        raise typer.Exit(1)


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
        framed = bytes.fromhex(capture.received_frame_hex)
        leading = bytes.fromhex(capture.leading_response_bytes_hex)
        decoded = decode_response(
            framed or leading, incomplete=not capture.report.frame_complete
        )
    except CaptureError as exc:
        error_console.print(f"Invalid capture: {exc}")
        raise typer.Exit(3) from None
    console.print(f"QSIdentify {__version__}")
    console.print(f"Capture:           {path}")
    console.print(f"Created:           {capture.created_utc}")
    console.print(f"Port:              {capture.port.device}")
    _print_decoded(decoded)
    console.print(f"Response bytes:    {len(bytes.fromhex(capture.received_frame_hex))}")


@app.command("doctor")
def doctor_command() -> None:
    failed = False
    table = Table(title="QSIdentify doctor")
    for column in ("Check", "Status", "Detail"):
        table.add_column(column)
    for check in run_checks():
        failed = failed or not check.ok
        table.add_row(check.name, "OK" if check.ok else "WARN", check.detail)
    console.print(table)
    if failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
