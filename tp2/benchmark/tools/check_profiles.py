#!/usr/bin/env python3
"""Vérifie que deux sdkconfig effectifs ne diffèrent que par le profil ChaCha."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

EXPECTED_DIFFERENCES = {
    "CONFIG_CRYPTOSE_PROFILE_ID": ('"baseline"', '"chacha20-poly1305"'),
    "CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305": (None, "y"),
    "CONFIG_MBEDTLS_CHACHA20_C": (None, "y"),
    "CONFIG_MBEDTLS_CHACHAPOLY_C": (None, "y"),
}
NOT_SET = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")


class ProfileDifferenceError(ValueError):
    pass


def parse_sdkconfig(content: str) -> dict[str, str | None]:
    configuration: dict[str, str | None] = {}
    for line in content.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            name, value = line.split("=", 1)
            configuration[name] = value
        elif match := NOT_SET.fullmatch(line):
            configuration[match.group(1)] = None
    return configuration


def validate_profile_difference(baseline_text: str, chacha_text: str) -> None:
    baseline = parse_sdkconfig(baseline_text)
    chacha = parse_sdkconfig(chacha_text)
    changed = {
        name: (baseline.get(name), chacha.get(name))
        for name in baseline.keys() | chacha.keys()
        if baseline.get(name) != chacha.get(name)
    }
    if changed != EXPECTED_DIFFERENCES:
        unexpected = {
            name: values
            for name, values in changed.items()
            if EXPECTED_DIFFERENCES.get(name) != values
        }
        missing = {
            name: values
            for name, values in EXPECTED_DIFFERENCES.items()
            if changed.get(name) != values
        }
        raise ProfileDifferenceError(
            f"différences inattendues={unexpected}; différences manquantes={missing}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("chacha", type=Path)
    arguments = parser.parse_args()
    try:
        validate_profile_difference(
            arguments.baseline.read_text(encoding="utf-8"),
            arguments.chacha.read_text(encoding="utf-8"),
        )
    except (OSError, ProfileDifferenceError) as error:
        print(f"ERREUR: {error}", file=sys.stderr)
        return 1
    print("Profils valides: seuls les quatre paramètres ChaCha attendus diffèrent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
