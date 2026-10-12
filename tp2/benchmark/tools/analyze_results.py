#!/usr/bin/env python3
"""Agrège les répétitions validées du benchmark CryptoSE en CSV."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from validate_jsonl import ValidationError, validate_stream


PROFILE_DIRECTORY = {
    "baseline": "baseline",
    "chacha20-poly1305": "chacha",
}


@dataclass(frozen=True, slots=True)
class SeriesMeasurement:
    workload: str
    profile: str
    algorithm: str
    operation: str
    payload_bytes: int
    cycles_median: int
    cycles_p95: int
    heap_delta_bytes: int
    stack_high_water_bytes: int
    flash_total_size: int


def _json_records(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as stream:
        validate_stream(stream)
    records: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if line.startswith("{"):
                value = json.loads(line)
                if isinstance(value, dict):
                    records.append(value)
    return records


def _flash_total_size(builds_root: Path, workload: str, profile: str) -> int:
    size_path = builds_root / workload / profile / "size.json"
    value = json.loads(size_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or type(value.get("total_size")) is not int:
        raise ValueError(f"total_size absent de {size_path}")
    total_size = value["total_size"]
    assert type(total_size) is int
    if total_size <= 0:
        raise ValueError(f"total_size invalide dans {size_path}")
    return total_size


def collect_series(raw_root: Path, builds_root: Path) -> list[SeriesMeasurement]:
    series: list[SeriesMeasurement] = []
    targets: set[str] = set()
    for capture in sorted(raw_root.glob("*/*.log")):
        workload = capture.parent.name
        records = _json_records(capture)
        metadata = next(
            (record for record in records if record.get("record") == "metadata"), None
        )
        if metadata is None or type(metadata.get("profile_id")) is not str:
            raise ValueError(f"métadonnées absentes de {capture}")
        targets.add(str(metadata["target"]))
        if len(targets) > 1:
            # Cycle counts only compare on one chip: ESP32 and ESP32-S3 differ in
            # their AES/SHA accelerators and memory buses.
            raise ValueError(
                f"cibles mélangées sous {raw_root}: {', '.join(sorted(targets))}"
            )
        profile_id = str(metadata["profile_id"])
        try:
            profile = PROFILE_DIRECTORY[profile_id]
        except KeyError as error:
            raise ValueError(f"profil inconnu dans {capture}: {profile_id}") from error
        flash_total_size = _flash_total_size(builds_root, workload, profile)
        for record in records:
            if record.get("record") != "measurement":
                continue
            series.append(
                SeriesMeasurement(
                    workload=workload,
                    profile=profile,
                    algorithm=str(record["algorithm"]),
                    operation=str(record["operation"]),
                    payload_bytes=int(record["payload_bytes"]),
                    cycles_median=int(record["cycles_median"]),
                    cycles_p95=int(record["cycles_p95"]),
                    heap_delta_bytes=int(record["heap_delta_bytes"]),
                    stack_high_water_bytes=int(record["stack_high_water_bytes"]),
                    flash_total_size=flash_total_size,
                )
            )
    if not series:
        raise ValueError(f"aucune capture trouvée sous {raw_root}")
    return series


def summarize_series(
    series: Iterable[SeriesMeasurement], *, required_repetitions: int = 3
) -> list[dict[str, str | int]]:
    """Agrège sans fusionner workload, profil, algorithme ni opération."""
    # TODO_STUDENT: grouper, vérifier le nombre de répétitions et calculer la synthèse.
    del series, required_repetitions
    raise NotImplementedError("agrégation étudiante non implémentée")


def write_csv(rows: list[dict[str, str | int]], output: Path) -> None:
    if not rows:
        raise ValueError("aucune ligne à écrire")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--builds-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    arguments = parser.parse_args()
    try:
        rows = summarize_series(
            collect_series(arguments.raw_root, arguments.builds_root),
            required_repetitions=arguments.repetitions,
        )
        write_csv(rows, arguments.output)
    except (
        OSError,
        ValueError,
        NotImplementedError,
        ValidationError,
        json.JSONDecodeError,
    ) as error:
        print(f"ERREUR: {error}", file=sys.stderr)
        return 1
    print(f"CSV écrit: {arguments.output} ({len(rows)} lignes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
