from pathlib import Path

from typer.testing import CliRunner

from qsidentify.cli import app
from qsidentify.models import SafetyClass
from qsidentify.protocol.commands import ALLOWLIST


def test_all_commands_are_read_only() -> None:
    assert ALLOWLIST
    assert all(command.safety is SafetyClass.READ_ONLY for command in ALLOWLIST)


def test_no_write_like_command_names() -> None:
    forbidden = ("write", "erase", "flash", "reset", "reboot")
    assert all(not any(word in command.name.lower() for word in forbidden) for command in ALLOWLIST)


def test_cli_has_no_arbitrary_transmit_option() -> None:
    runner = CliRunner()
    for command in ("probe", "monitor", "matrix"):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0
        lowered = result.stdout.lower()
        assert "--hex" not in lowered
        assert "--frame" not in lowered
        assert "--transmit" not in lowered


def test_no_write_capable_modules_exist() -> None:
    names = {path.name.lower() for path in Path("src/qsidentify").rglob("*.py")}
    assert not names & {"eeprom.py", "flash.py", "firmware.py", "writer.py"}


def test_matrix_implementation_delegates_to_safe_probe() -> None:
    source = Path("src/qsidentify/cli.py").read_text()
    start = source.index("def matrix_command(")
    end = source.index('@app.command("decode")')
    matrix_source = source[start:end]
    assert "probe_port(" in matrix_source
    assert ".write(" not in matrix_source
    assert "encode_frame" not in matrix_source
