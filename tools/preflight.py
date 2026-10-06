#!/usr/bin/env python3
"""Read-only host and ESP32-S3 readiness checks for the CryptoSE labs."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
from typing import Iterable, NamedTuple, Sequence


SCHEMA_VERSION = 1
SERIAL_PREFIXES = ("/dev/ttyACM", "/dev/ttyUSB")


def locate_version_file(script_path: pathlib.Path) -> pathlib.Path:
    """Find the nearest package or repository ESP-IDF version pin."""
    resolved = script_path.resolve()
    for directory in (resolved.parent, *resolved.parents):
        candidate = directory / "ESP_IDF_VERSION"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("ESP_IDF_VERSION absent au-dessus du preflight")


VERSION_FILE = locate_version_file(pathlib.Path(__file__))
REPOSITORY_ROOT = VERSION_FILE.parent


class Check(NamedTuple):
    name: str
    status: str
    detail: str


class Report:
    def __init__(self, expected_idf: str, checks: Sequence[Check]) -> None:
        self.expected_idf = expected_idf
        self.checks = list(checks)

    @property
    def exit_code(self) -> int:
        return int(any(check.status == "FAIL" for check in self.checks))

    def to_json(self) -> str:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "expected_idf": self.expected_idf,
            "checks": [check._asdict() for check in self.checks],
            "ready": self.exit_code == 0,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def to_text(self) -> str:
        width = max(len(check.name) for check in self.checks)
        lines = [
            f"[{check.status:<4}] {check.name:<{width}}  {check.detail}"
            for check in self.checks
        ]
        lines.append("READY" if self.exit_code == 0 else "NOT READY")
        return "\n".join(lines)


def parse_idf_version(output: str) -> str | None:
    match = re.search(r"\bESP-IDF\s+v?(\d+\.\d+(?:\.\d+)?)\b", output)
    return match.group(1) if match else None


def is_wsl(kernel_release: str) -> bool:
    lowered = kernel_release.lower()
    return "microsoft" in lowered or "wsl" in lowered


def filter_serial_ports(candidates: Iterable[pathlib.Path]) -> list[str]:
    return sorted(
        str(path) for path in candidates if str(path).startswith(SERIAL_PREFIXES)
    )


def discover_serial_ports() -> list[str]:
    dev = pathlib.Path("/dev")
    candidates = [*dev.glob("ttyACM*"), *dev.glob("ttyUSB*")]
    return filter_serial_ports(candidates)


def run_command(command: Sequence[str], timeout: float = 15.0) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, f"command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"command timed out after {timeout:g}s: {command[0]}"

    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    return result.returncode, output


def read_expected_idf() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def check_idf_version(output: str, expected: str, returncode: int = 0) -> Check:
    actual = parse_idf_version(output)
    if returncode != 0 or actual is None:
        return Check(
            "esp-idf",
            "FAIL",
            "idf.py is unavailable; activate the pinned ESP-IDF environment with EIM or export.sh",
        )
    if actual != expected:
        return Check("esp-idf", "FAIL", f"found {actual}; expected {expected}")
    return Check("esp-idf", "PASS", f"ESP-IDF v{actual}")


def idf_version_command() -> list[str]:
    executable = shutil.which("idf.py")
    if executable is not None:
        return [executable, "--version"]
    idf_path = os.environ.get("IDF_PATH")
    python_env = os.environ.get("IDF_PYTHON_ENV_PATH")
    if idf_path and python_env:
        script = pathlib.Path(idf_path) / "tools/idf.py"
        python = pathlib.Path(python_env) / "bin/python"
        if script.is_file() and python.is_file():
            return [str(python), str(script), "--version"]
    return ["idf.py", "--version"]


def check_serial_ports(ports: Sequence[str], require_hardware: bool) -> Check:
    if ports:
        return Check("serial", "PASS", ", ".join(ports))
    status = "FAIL" if require_hardware else "WARN"
    return Check("serial", status, "no /dev/ttyACM* or /dev/ttyUSB* port detected")


def check_command(name: str) -> Check:
    path = shutil.which(name)
    if path is None:
        return Check(name, "FAIL", "command not found")
    return Check(name, "PASS", path)


def usbipd_command_candidates() -> list[str]:
    candidates = [
        path
        for name in ("usbipd.exe", "usbipd")
        if (path := shutil.which(name)) is not None
    ]
    candidates.append("/mnt/c/Program Files/usbipd-win/usbipd.exe")
    return list(dict.fromkeys(candidates))


def check_usbipd(running_under_wsl: bool) -> Check:
    if not running_under_wsl:
        return Check("usbipd", "SKIP", "not running under WSL")

    failures: list[str] = []
    for executable in usbipd_command_candidates():
        returncode, output = run_command([executable, "list"])
        if returncode == 127:
            continue
        if returncode != 0:
            failures.append(output or f"exit code {returncode}")
            continue

        attached = [line.strip() for line in output.splitlines() if "Attached" in line]
        if attached:
            return Check("usbipd", "PASS", "; ".join(attached))
        return Check(
            "usbipd", "WARN", "installed, but no USB device is attached to WSL"
        )

    if failures:
        return Check("usbipd", "WARN", f"usbipd query failed: {failures[-1]}")
    return Check("usbipd", "WARN", "usbipd-win is not installed on Windows")


def parse_board_summary(output: str) -> str:
    fields: list[str] = []
    for pattern, prefix in (
        (r"^Chip type:\s*(.+)$", ""),
        (r"^Features:\s*(.+)$", ""),
        (r"^Detected flash size:\s*(.+)$", "flash "),
    ):
        match = re.search(pattern, output, flags=re.MULTILINE)
        if match is not None:
            fields.append(f"{prefix}{match.group(1).strip()}")
    return "; ".join(fields) or "ESP32-S3 responded to esptool"


def check_board(port: str | None, require_hardware: bool) -> Check:
    if port is None:
        status = "FAIL" if require_hardware else "SKIP"
        return Check(
            "esp32", status, "hardware probe not requested or no serial port found"
        )

    returncode, output = run_command(
        ["esptool", "--chip", "esp32", "--port", port, "flash-id"],
        timeout=30.0,
    )
    if returncode != 0:
        return Check(
            "esp32", "FAIL", output or f"esptool failed with code {returncode}"
        )

    return Check("esp32", "PASS", parse_board_summary(output))


def collect_report(
    expected: str, require_hardware: bool, requested_port: str | None
) -> Report:
    kernel_release = platform.release()
    running_under_wsl = is_wsl(kernel_release)
    ports = discover_serial_ports()
    selected_port = requested_port or (ports[0] if ports and require_hardware else None)

    idf_returncode, idf_output = run_command(idf_version_command())
    checks = [
        Check("platform", "PASS", f"{platform.system()} {kernel_release}"),
        Check("wsl", "PASS" if running_under_wsl else "SKIP", str(running_under_wsl)),
        check_command("python3"),
        check_command("cmake"),
        check_command("ninja"),
        check_idf_version(idf_output, expected, idf_returncode),
        check_usbipd(running_under_wsl),
        check_serial_ports(ports, require_hardware),
        check_board(selected_port, require_hardware),
    ]
    return Report(expected_idf=expected, checks=checks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run read-only CryptoSE ESP-IDF and ESP32-S3 readiness checks."
    )
    parser.add_argument(
        "--expected-idf",
        default=None,
        help="override the version stored in ESP_IDF_VERSION",
    )
    parser.add_argument(
        "--require-hardware",
        action="store_true",
        help="fail unless an ESP32-S3 responds through a serial port",
    )
    parser.add_argument("--port", help="serial port to probe, for example /dev/ttyUSB0")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expected = args.expected_idf or read_expected_idf()
    report = collect_report(expected, args.require_hardware, args.port)
    print(report.to_json() if args.json else report.to_text())
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
