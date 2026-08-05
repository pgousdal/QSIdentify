import tarfile
import zipfile
from importlib.resources import files
from pathlib import Path


def test_catalogs_load_from_package_resources() -> None:
    data = files("qsidentify.drivers.quansheng.data")
    assert '"catalog_version": "2026.08"' in data.joinpath("firmware_catalog.json").read_text()
    assert '"schema_version": 1' in data.joinpath("hardware_catalog.json").read_text()


def test_built_artifacts_have_required_and_no_forbidden_members() -> None:
    wheel = Path("dist/qsidentify-1.2.0-py3-none-any.whl")
    sdist = Path("dist/qsidentify-1.2.0.tar.gz")
    if not wheel.exists() or not sdist.exists():
        return
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()
    required = (
        "qsidentify/drivers/quansheng/driver.py",
        "qsidentify/drivers/quansheng/data/firmware_catalog.json",
        "qsidentify/drivers/quansheng/data/hardware_catalog.json",
    )
    assert all(any(name.endswith(item) for name in wheel_names) for item in required)
    assert all(any(name.endswith(item) for name in sdist_names) for item in required)
    forbidden = ("/.git/", "/.venv/", "/.idea/", "/.vscode/", "tests/fixtures/captures")
    assert not any(token in name for name in wheel_names + sdist_names for token in forbidden)
