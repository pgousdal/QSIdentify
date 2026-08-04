from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .capture import build_capture, read_capture, write_capture
from .doctor import run_checks
from .ports import choose_auto_port, find_port, list_serial_ports
from .probe import probe_port
from .protocol.decoder import decode_response

app = typer.Typer(
    help="Read-only identification and diagnostics for Quansheng radios.",
    no_args_is_help=True,
)
console = Console()


@app.command("ports")
def ports_command() -> None:
    ports = list_serial_ports()
    if not ports:
        console.print("[yellow]No serial ports found.[/yellow]")
        raise typer.Exit(1)

    table = Table(title="Serial ports")
    table.add_column("Device")
    table.add_column("Description")
    table.add_column("VID:PID")
    table.add_column("Manufacturer")
    for port in ports:
        table.add_row(
            port.device,
            port.description or "-",
            port.vid_pid or "-",
            port.manufacturer or "-",
        )
    console.print(table)


@app.command("probe")
def probe_command(
    device: Annotated[str | None, typer.Argument()] = None,
    auto: Annotated[bool, typer.Option("--auto")] = False,
    baud_rate: Annotated[int, typer.Option("--baud")] = 38400,
    timeout: Annotated[float, typer.Option("--timeout")] = 1.0,
    trace: Annotated[bool, typer.Option("--trace")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    capture_path: Annotated[Path | None, typer.Option("--capture")] = None,
) -> None:
    if auto and device:
        raise typer.BadParameter("Use either a device argument or --auto, not both.")
    if not auto and not device:
        raise typer.BadParameter("Specify a serial device or use --auto.")

    port = choose_auto_port() if auto else find_port(device or "")
    try:
        result = probe_port(port, baud_rate=baud_rate, timeout=timeout)
    except Exception as exc:
        console.print(f"[red]Probe failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if capture_path is not None or trace:
        path = capture_path or Path("captures") / "latest.json"
        write_capture(path, build_capture(result))
        if not as_json:
            console.print(f"Capture: [bold]{path}[/bold]")

    if as_json:
        console.print_json(json.dumps(result.report.to_dict()))
        return

    report = result.report
    console.print("[bold]QSIdentify 0.1.0[/bold]")
    console.print(f"Port:              {report.port.device}")
    console.print(f"VID:PID:           {report.port.vid_pid or '-'}")
    console.print(f"Baud rate:         {report.baud_rate}")
    console.print(f"Operating mode:    {report.operating_mode}")
    console.print(f"Response received: {'yes' if report.response_received else 'no'}")
    console.print(f"Reported version:  {report.reported_version or '-'}")
    console.print(f"Detected protocol: {report.detected_protocol or '-'}")
    console.print(f"Inferred family:   {report.inferred_family or '-'}")
    console.print(f"Confidence:        {report.confidence.value}")
    if trace:
        console.print(f"TX: {result.exchange.request.hex(' ')}")
        console.print(f"RX: {result.exchange.response.hex(' ') or '-'}")
    for warning in report.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


@app.command("decode")
def decode_command(path: Path) -> None:
    capture = read_capture(path)
    response = bytes.fromhex(capture.response_hex)
    decoded = decode_response(response)

    console.print(f"Capture:           {path}")
    console.print(f"Created:           {capture.created_utc}")
    console.print(f"Port:              {capture.port.device}")
    console.print(f"Reported version:  {decoded.reported_version or '-'}")
    console.print(f"Detected protocol: {decoded.detected_protocol or '-'}")
    console.print(f"Inferred family:   {decoded.inferred_family or '-'}")
    console.print(f"Confidence:        {decoded.confidence.value}")
    console.print(f"Response bytes:    {len(response)}")


@app.command("doctor")
def doctor_command() -> None:
    failed = False
    table = Table(title="QSIdentify doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for check in run_checks():
        failed = failed or not check.ok
        table.add_row(check.name, "OK" if check.ok else "FAIL", check.detail)
    console.print(table)
    if failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
