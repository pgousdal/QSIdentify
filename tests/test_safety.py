from qsidentify.protocol.commands import ALLOWLIST, SafetyClass


def test_all_commands_are_read_only() -> None:
    assert ALLOWLIST
    assert all(command.safety is SafetyClass.READ_ONLY for command in ALLOWLIST)


def test_no_write_like_command_names() -> None:
    forbidden = ("write", "erase", "flash", "reset", "reboot")
    for command in ALLOWLIST:
        name = command.name.lower()
        assert not any(word in name for word in forbidden)
