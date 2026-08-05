import json
from pathlib import Path

import pytest

from qsidentify.catalog import CatalogError, load_firmware_catalog, load_hardware_records


def catalog_data() -> dict[str, object]:
    path = Path("src/qsidentify/drivers/quansheng/data/firmware_catalog.json")
    return json.loads(path.read_text())  # type: ignore[no-any-return]


def write_catalog(tmp_path: Path, data: dict[str, object]) -> Path:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data))
    return path


def test_packaged_catalog_is_valid_and_deterministically_ordered() -> None:
    first = load_firmware_catalog()
    second = load_firmware_catalog()
    assert first == second
    assert [item.id for item in first.entries] == sorted(item.id for item in first.entries)
    assert first.catalog_version == "2026.08"
    assert len(load_hardware_records()) == 3


@pytest.mark.parametrize("mutation", ["malformed", "duplicate-id", "missing-source"])
def test_invalid_catalogs_are_rejected(tmp_path: Path, mutation: str) -> None:
    if mutation == "malformed":
        path = tmp_path / "catalog.json"
        path.write_text("{")
    else:
        data = catalog_data()
        entries = data["entries"]
        assert isinstance(entries, list)
        if mutation == "duplicate-id":
            entries[1]["id"] = entries[0]["id"]
        else:
            entries[0]["sources"] = []
        path = write_catalog(tmp_path, data)
    with pytest.raises(CatalogError):
        load_firmware_catalog(path)
