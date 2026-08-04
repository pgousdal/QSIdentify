from qsidentify.models import PortInfo


def test_vid_pid_format() -> None:
    port = PortInfo(device="/dev/ttyUSB0", vid=0x1A86, pid=0x7523)
    assert port.vid_pid == "1a86:7523"


def test_missing_vid_pid() -> None:
    assert PortInfo(device="COM3").vid_pid is None
