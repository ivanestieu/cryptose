from __future__ import annotations

import sys
from pathlib import Path

import pytest


TOOLS = Path(__file__).parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from analyze_results import (  # noqa: E402
    SeriesMeasurement,
    collect_series,
    summarize_series,
)
from test_validate_jsonl import document, valid_records  # noqa: E402


def test_groups_three_repetitions_without_mixing_boundaries() -> None:
    series = [
        SeriesMeasurement(
            workload="telemetry-64",
            profile="baseline",
            algorithm="aes-256-gcm",
            operation="import-encrypt-decrypt",
            payload_bytes=64,
            cycles_median=cycles,
            cycles_p95=cycles + 10,
            heap_delta_bytes=heap,
            stack_high_water_bytes=stack,
            flash_total_size=240_000,
        )
        for cycles, heap, stack in (
            (100, 20, 1_000),
            (110, 25, 900),
            (105, 22, 950),
        )
    ]
    rows = summarize_series(series, required_repetitions=3)
    assert rows == [
        {
            "workload": "telemetry-64",
            "profile": "baseline",
            "algorithm": "aes-256-gcm",
            "operation": "import-encrypt-decrypt",
            "payload_bytes": 64,
            "series_count": 3,
            "cycles_median_of_medians": 105,
            "cycles_median_min": 100,
            "cycles_median_max": 110,
            "cycles_p95_max": 120,
            "heap_delta_max_bytes": 25,
            "stack_high_water_min_bytes": 900,
            "flash_total_size_bytes": 240_000,
            "flash_delta_vs_baseline_bytes": 0,
        }
    ]


def test_rejects_an_incomplete_group() -> None:
    series = [
        SeriesMeasurement(
            workload="block-1024",
            profile="baseline",
            algorithm="sha-256",
            operation="hash",
            payload_bytes=1024,
            cycles_median=10,
            cycles_p95=11,
            heap_delta_bytes=0,
            stack_high_water_bytes=1_000,
            flash_total_size=240_000,
        )
    ]
    with pytest.raises(ValueError, match="3 répétitions"):
        summarize_series(series, required_repetitions=3)


def test_refuses_to_mix_captures_from_different_targets(tmp_path: Path) -> None:
    for target, chip_model in (("esp32", "esp32"), ("esp32s3", "esp32-s3")):
        capture = tmp_path / "raw" / "block-1024" / f"{target}.log"
        capture.parent.mkdir(parents=True, exist_ok=True)
        records = valid_records(target=target, chip_model=chip_model)
        capture.write_text(document(records), encoding="utf-8")
    size = tmp_path / "builds" / "block-1024" / "baseline" / "size.json"
    size.parent.mkdir(parents=True)
    size.write_text('{"total_size": 240000}', encoding="utf-8")
    with pytest.raises(ValueError, match="cibles mélangées"):
        collect_series(tmp_path / "raw", tmp_path / "builds")
