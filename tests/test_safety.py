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
    result = CliRunner().invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    lowered = result.stdout.lower()
    assert "--hex" not in lowered
    assert "--frame" not in lowered
    assert "--transmit" not in lowered


def test_no_write_capable_modules_exist() -> None:
    names = {path.name.lower() for path in Path("src/qsidentify").rglob("*.py")}
    assert not names & {"eeprom.py", "flash.py", "firmware.py", "writer.py"}
