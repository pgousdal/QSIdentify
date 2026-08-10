from __future__ import annotations

import re
import tomllib
from pathlib import Path

from qsidentify import __version__

ROOT = Path(__file__).parents[1]


def _relative_markdown_links(path: Path) -> list[Path]:
    links: list[Path] = []
    for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "#")):
            continue
        links.append((path.parent / target.split("#", 1)[0]).resolve())
    return links


def test_readme_links_and_current_claims() -> None:
    readme = ROOT / "README.md"
    assert all(path.exists() for path in _relative_markdown_links(readme))
    text = readme.read_text(encoding="utf-8")
    assert "QSIdentify 1.1.0" not in text
    assert "does not write EEPROM" in text
    assert "Reported version:  2.01.36" in text
    assert "MCU" in text and "does not establish" in text


def test_documentation_index_links() -> None:
    index = ROOT / "docs" / "README.md"
    assert all(path.exists() for path in _relative_markdown_links(index))


def test_package_metadata_matches_canonical_version() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    assert project["description"] == (
        "Read-only identification, diagnostics, and evidence tooling for programmable radios"
    )
    assert "Programming Language :: Python :: 3.11" in project["classifiers"]
    assert project["urls"]["Repository"].endswith("pgousdal/QSIdentify")
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
