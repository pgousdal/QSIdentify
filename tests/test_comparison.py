from dataclasses import replace

from test_capture import result_fixture

from qsidentify.capture import build_capture
from qsidentify.comparison import compare_captures


def test_capture_comparison_reports_stable_descriptive_metrics() -> None:
    first = build_capture(result_fixture(response=b"\x00\x01\x02"))
    second = build_capture(result_fixture(response=b"\x00\x01\x03"))
    comparison = compare_captures((first, second))
    assert not comparison.exact_match
    assert comparison.common_prefix == b"\x00\x01"
    assert comparison.common_suffix == b""
    assert comparison.common_positions == ((0, 0), (1, 1))
    assert len(comparison.summaries[0].sha256) == 64
    assert comparison.summaries[0].null_percentage == 100 / 3


def test_exact_empty_responses_compare_without_division_errors() -> None:
    empty = build_capture(result_fixture(response=b""))
    comparison = compare_captures((empty, replace(empty, created_utc=empty.created_utc)))
    assert comparison.exact_match
    assert comparison.summaries[0].null_percentage == 0.0
