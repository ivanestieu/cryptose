#!/usr/bin/env python3
"""Assemble l'archive de rendu du TP2 à partir du projet, des mesures et du rapport.

    python3 tools/make_submission.py --data ../submission --report ../rapport.md \\
        --output ../tp2-nom1-nom2.zip

L'archive contient le code source (sans répertoire de compilation), les captures, les
configurations, le résumé dérivé, le rapport, les preuves produites ici (tests hôtes,
validation de chaque capture) et un fichier SHA256SUMS. Rien n'est bloquant : ce qui ne
marche pas doit être visible dans les preuves et expliqué dans le rapport.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from validate_jsonl import ValidationError, validate_stream

PROJECT = Path(__file__).resolve().parents[1]
SOURCE_ITEMS = (
    "CMakeLists.txt",
    "sdkconfig.defaults",
    "main",
    "profiles",
    "workloads",
    "tests",
    "tools",
    "README.md",
)
SKIPPED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache"}


def copy_source(destination: Path) -> None:
    destination.mkdir(parents=True)
    for item in SOURCE_ITEMS:
        source = PROJECT / item
        if source.is_dir():
            shutil.copytree(
                source,
                destination / item,
                ignore=shutil.ignore_patterns(*SKIPPED_PARTS),
            )
        elif source.is_file():
            shutil.copy2(source, destination / item)


def host_test_evidence() -> str:
    completed = subprocess.run(
        ["bash", "tools/run_host_tests.sh"], cwd=PROJECT, capture_output=True, text=True
    )
    verdict = (
        "SUCCÈS"
        if completed.returncode == 0
        else f"ÉCHEC (code {completed.returncode})"
    )
    return f"Tests hôtes : {verdict}\n\n{completed.stdout}\n{completed.stderr}"


def capture_evidence(raw: Path) -> str:
    lines = []
    for log in sorted(raw.glob("*/*.log")):
        try:
            with log.open(encoding="utf-8") as stream:
                summary = validate_stream(stream)
            lines.append(
                f"OK    {log.relative_to(raw)} ({summary.measurement_records} mesures)"
            )
        except (OSError, ValidationError) as error:
            lines.append(f"ÉCHEC {log.relative_to(raw)} : {error}")
    return "\n".join(lines or ["aucune capture"]) + "\n"


def write_checksums(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}"
        for path in files
    ]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--data", type=Path, required=True, help="répertoire produit par run_matrix.py"
    )
    parser.add_argument(
        "--report", type=Path, required=True, help="rapport.md ou rapport.pdf"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="archive .zip à créer"
    )
    arguments = parser.parse_args()
    if arguments.report.suffix not in {".md", ".pdf"} or not arguments.report.is_file():
        parser.error("le rapport doit être un fichier .md ou .pdf existant")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "submission"
        copy_source(root / "source")
        # The validator checks the ESP-IDF version against the pin found above it.
        pin = next(
            d / "ESP_IDF_VERSION"
            for d in PROJECT.parents
            if (d / "ESP_IDF_VERSION").is_file()
        )
        shutil.copy2(pin, root / "ESP_IDF_VERSION")
        for part in ("raw", "builds", "derived"):
            if (arguments.data / part).is_dir():
                shutil.copytree(arguments.data / part, root / part)
        shutil.copy2(arguments.report, root / f"rapport{arguments.report.suffix}")
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "host-tests.txt").write_text(host_test_evidence(), encoding="utf-8")
        (evidence / "captures.txt").write_text(
            capture_evidence(root / "raw"), encoding="utf-8"
        )
        write_checksums(root)
        with ZipFile(arguments.output, "w", compression=ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(root.parent).as_posix())
        print((evidence / "host-tests.txt").read_text(encoding="utf-8").splitlines()[0])
        print((evidence / "captures.txt").read_text(encoding="utf-8"), end="")
    print(f"Archive écrite : {arguments.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
