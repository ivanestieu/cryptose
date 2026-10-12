#!/usr/bin/env python3
"""Compile les 4 configurations, puis flashe et capture les séries du benchmark.

À lancer depuis la racine du projet benchmark, dans un terminal ESP-IDF activé :

    python3 tools/run_matrix.py --port /dev/ttyUSB0 --target esp32 --output ../submission

Résultat : <output>/builds/<workload>/<profil>/{sdkconfig,size.json} et
<output>/raw/<workload>/<profil>-NN.log, chaque capture étant validée au passage.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from validate_jsonl import ValidationError, validate_stream

WORKLOADS = ("telemetry-64", "block-1024")
PROFILES = {"baseline": "baseline", "chacha": "chacha20-poly1305"}
MEASUREMENTS = {"baseline": 6, "chacha": 7}
PROJECT = Path(__file__).resolve().parents[1]


def idf_py() -> list[str]:
    # EIM's activation script exposes idf.py as a shell function, invisible to subprocess.
    executable = shutil.which("idf.py")
    if executable is not None:
        return [executable]
    if "IDF_PATH" not in os.environ:
        sys.exit("ESP-IDF n'est pas activé dans ce terminal (IDF_PATH absent)")
    return [sys.executable, str(Path(os.environ["IDF_PATH"]) / "tools" / "idf.py")]


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=PROJECT, check=True)


def build(workload: str, profile: str, target: str, build_dir: Path) -> None:
    shutil.rmtree(build_dir, ignore_errors=True)
    defaults = f"sdkconfig.defaults;workloads/{workload}.sdkconfig.defaults;profiles/{PROFILES[profile]}.sdkconfig.defaults"
    run(
        [
            *idf_py(),
            "-B",
            str(build_dir),
            "-D",
            f"SDKCONFIG={build_dir / 'sdkconfig'}",
            "-D",
            f"SDKCONFIG_DEFAULTS={defaults}",
            "set-target",
            target,
            "build",
        ]
    )
    run(
        [
            *idf_py(),
            "-B",
            str(build_dir),
            "size",
            "--format",
            "json2",
            "--output-file",
            str(build_dir / "size.json"),
        ]
    )


def capture(port: str, destination: Path, expected: int, timeout: float) -> None:
    import serial  # fourni par l'environnement Python d'ESP-IDF

    measurements = 0
    with (
        serial.Serial(port, 115200, timeout=0.2) as link,
        destination.open("w", encoding="utf-8") as sink,
    ):
        link.dtr = False
        link.rts = True  # reset de la carte par la broche EN
        time.sleep(0.1)
        # Carte tenue en reset : jeter ce qu'elle a écrit avant, sinon une ligne
        # coupée par le reset ouvre la capture.
        link.reset_input_buffer()
        link.rts = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and measurements < expected:
            line = link.readline().decode(errors="replace").rstrip("\r\n")
            if line:
                sink.write(line + "\n")
                measurements += (
                    line.startswith("{") and '"record":"measurement"' in line
                )
    if measurements < expected:
        raise TimeoutError(
            f"{destination}: {measurements}/{expected} mesures après {timeout:.0f} s"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--port", required=True)
    parser.add_argument("--target", required=True, choices=("esp32", "esp32s3"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument(
        "--timeout", type=float, default=300.0, help="secondes par capture"
    )
    parser.add_argument(
        "--build-only", action="store_true", help="compiler sans flasher"
    )
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    work = PROJECT / "build-matrix"
    failures: list[str] = []

    for workload in WORKLOADS:
        for profile in PROFILES:
            build_dir = work / workload / profile
            build(workload, profile, arguments.target, build_dir)
            kept = output / "builds" / workload / profile
            kept.mkdir(parents=True, exist_ok=True)
            for name in ("sdkconfig", "size.json"):
                shutil.copy2(build_dir / name, kept / name)
        run(
            [
                sys.executable,
                "tools/check_profiles.py",
                str(work / workload / "baseline" / "sdkconfig"),
                str(work / workload / "chacha" / "sdkconfig"),
            ]
        )

    if arguments.build_only:
        return 0
    for workload in WORKLOADS:
        for profile in PROFILES:
            build_dir = work / workload / profile
            run([*idf_py(), "-B", str(build_dir), "-p", arguments.port, "flash"])
            for repetition in range(1, arguments.repetitions + 1):
                log = output / "raw" / workload / f"{profile}-{repetition:02d}.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                try:
                    capture(
                        arguments.port, log, MEASUREMENTS[profile], arguments.timeout
                    )
                    with log.open(encoding="utf-8") as stream:
                        validate_stream(stream)
                    print(f"OK   {log.relative_to(output)}", flush=True)
                except (TimeoutError, ValidationError) as error:
                    failures.append(f"{log.relative_to(output)}: {error}")
                    print(f"ÉCHEC {failures[-1]}", flush=True)
    for failure in failures:
        print(f"ÉCHEC {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
