#!/usr/bin/env python3
"""Valide strictement le contrat JSONL produit par le benchmark CryptoSE."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

SCHEMA = "cryptose.benchmark.v2"
PSA_SUCCESS = 0
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_RUNTIME_DIAGNOSTIC = re.compile(
    r"\btask_wdt\b|\btask\s+watchdog\b|\bbacktrace\b", re.IGNORECASE
)
ALGORITHM_OPERATIONS = {
    "aes-256-gcm": ("import-encrypt-decrypt", True),
    "sha-256": ("hash", True),
    "hmac-sha-256": ("import-mac", True),
    "ecdh-p256": ("two-keygen-two-agreements", False),
    "x25519": ("two-keygen-two-agreements", False),
    "ecdsa-p256-sha-256": ("hash-keygen-sign-verify", True),
}
CHACHA_ALGORITHM = "chacha20-poly1305"
# The course fleet mixes classic ESP32 and ESP32-S3 boards: idf.py target -> chip model.
TARGET_CHIP_MODELS = {"esp32": "esp32", "esp32s3": "esp32-s3"}
# Every course image declares 4 MiB of flash, the smallest chip in the fleet.
FLASH_SIZE_MB = 4

METADATA_FIELDS = {
    "schema",
    "record",
    "idf_version",
    "target",
    "profile_id",
    "chip_model",
    "chip_revision",
    "chip_cores",
    "benchmark_core",
    "cpu_hz",
    "iterations",
    "warmup_iterations",
    "payload_bytes",
    "task_stack_bytes",
    "optimization",
    "aes_hardware_acceleration",
    "sha_hardware_acceleration",
    "flash_size_mb",
    "app_elf_sha256",
    "sdkconfig_sha256",
    "chacha20_poly1305_enabled",
}
CORRECTNESS_FIELDS = {"schema", "record", "algorithm", "status", "psa_status"}
MEASUREMENT_FIELDS = {
    "schema",
    "record",
    "algorithm",
    "operation",
    "status",
    "attempts",
    "valid_samples",
    "payload_bytes",
    "benchmark_core",
    "cycles_min",
    "cycles_median",
    "cycles_p95",
    "cycles_max",
    "latency_ns_min",
    "latency_ns_median",
    "latency_ns_p95",
    "latency_ns_max",
    "heap_before_bytes",
    "heap_min_bytes",
    "heap_delta_bytes",
    "stack_high_water_bytes",
}


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ValidationSummary:
    metadata_records: int
    correctness_records: int
    measurement_records: int


def _json_records(stream: TextIO) -> list[tuple[int, dict[str, object]]]:
    records: list[tuple[int, dict[str, object]]] = []
    for line_number, raw_line in enumerate(stream, start=1):
        if FORBIDDEN_RUNTIME_DIAGNOSTIC.search(raw_line) is not None:
            raise ValidationError(
                f"ligne {line_number}: watchdog ou backtrace détecté dans la capture"
            )
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValidationError(
                f"ligne {line_number}: JSON invalide: {error.msg}"
            ) from error
        if type(record) is not dict:
            raise ValidationError(f"ligne {line_number}: un objet JSON est attendu")
        records.append((line_number, record))
    if not records:
        raise ValidationError("aucun enregistrement JSONL trouvé")
    return records


def _exact_fields(
    record: dict[str, object], expected: set[str], line_number: int
) -> None:
    unknown = record.keys() - expected
    if unknown:
        raise ValidationError(
            f"ligne {line_number}: champs inconnus: {', '.join(sorted(unknown))}"
        )
    missing = expected - record.keys()
    if missing:
        raise ValidationError(
            f"ligne {line_number}: champs manquants: {', '.join(sorted(missing))}"
        )


def _exact_type(
    record: dict[str, object], field: str, expected: type, line_number: int
) -> object:
    value = record[field]
    if type(value) is not expected:
        raise ValidationError(
            f"ligne {line_number}: {field} doit être de type {expected.__name__}"
        )
    return value


def _integer(
    record: dict[str, object], field: str, line_number: int, *, minimum: int = 0
) -> int:
    value = _exact_type(record, field, int, line_number)
    assert type(value) is int
    if value < minimum:
        raise ValidationError(
            f"ligne {line_number}: {field} doit être supérieur ou égal à {minimum}"
        )
    return value


def _bounded_integer(
    record: dict[str, object],
    field: str,
    line_number: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = _integer(record, field, line_number, minimum=minimum)
    if value > maximum:
        raise ValidationError(
            f"ligne {line_number}: {field} doit être compris entre {minimum} et {maximum}"
        )
    return value


def _string(record: dict[str, object], field: str, line_number: int) -> str:
    value = _exact_type(record, field, str, line_number)
    assert type(value) is str
    if not value:
        raise ValidationError(f"ligne {line_number}: {field} ne doit pas être vide")
    return value


def _validate_envelope(record: dict[str, object], line_number: int) -> None:
    if record.get("schema") != SCHEMA:
        raise ValidationError(f"ligne {line_number}: schéma incompatible")
    if type(record.get("record")) is not str:
        raise ValidationError(f"ligne {line_number}: record doit être de type str")


def _expected_idf_version() -> str:
    for directory in Path(__file__).resolve().parents:
        version_file = directory / "ESP_IDF_VERSION"
        if version_file.is_file():
            return f"v{version_file.read_text(encoding='utf-8').strip()}"
    raise ValidationError("fichier ESP_IDF_VERSION introuvable au-dessus du validateur")


def _validate_metadata(
    record: dict[str, object], line_number: int
) -> tuple[dict[str, int], set[str]]:
    _exact_fields(record, METADATA_FIELDS, line_number)
    _validate_envelope(record, line_number)
    if record["record"] != "metadata":
        raise ValidationError("le premier enregistrement doit contenir les métadonnées")
    if _string(record, "idf_version", line_number) != _expected_idf_version():
        raise ValidationError(f"ligne {line_number}: version ESP-IDF non verrouillée")
    target = _string(record, "target", line_number)
    if target not in TARGET_CHIP_MODELS:
        raise ValidationError(f"ligne {line_number}: cible hors du parc: {target}")
    if _string(record, "chip_model", line_number) != TARGET_CHIP_MODELS[target]:
        raise ValidationError(
            f"ligne {line_number}: modèle de puce incohérent avec la cible {target}"
        )

    profile_id = _string(record, "profile_id", line_number)
    chacha_enabled = _exact_type(record, "chacha20_poly1305_enabled", bool, line_number)
    if profile_id not in {"baseline", "chacha20-poly1305"}:
        raise ValidationError(f"ligne {line_number}: profil inconnu")
    if (profile_id == "chacha20-poly1305") is not chacha_enabled:
        raise ValidationError(
            f"ligne {line_number}: profil et activation ChaCha incohérents"
        )

    chip_revision = _integer(record, "chip_revision", line_number)
    chip_cores = _integer(record, "chip_cores", line_number, minimum=1)
    benchmark_core = _integer(record, "benchmark_core", line_number)
    if benchmark_core >= chip_cores:
        raise ValidationError(
            f"ligne {line_number}: benchmark_core hors des cœurs disponibles"
        )
    cpu_hz = _integer(record, "cpu_hz", line_number, minimum=1)
    if cpu_hz != 240_000_000:
        raise ValidationError(
            f"ligne {line_number}: cpu_hz doit être verrouillé à 240000000"
        )
    iterations = _integer(record, "iterations", line_number, minimum=1)
    if iterations > 256:
        raise ValidationError(f"ligne {line_number}: iterations dépasse 256")
    warmup_iterations = _bounded_integer(
        record, "warmup_iterations", line_number, minimum=1, maximum=32
    )
    payload_bytes = _bounded_integer(
        record, "payload_bytes", line_number, minimum=16, maximum=4096
    )
    task_stack_bytes = _bounded_integer(
        record, "task_stack_bytes", line_number, minimum=8192, maximum=32768
    )
    if _string(record, "optimization", line_number) != "performance":
        raise ValidationError(
            f"ligne {line_number}: optimisation différente de performance"
        )
    if _exact_type(record, "aes_hardware_acceleration", bool, line_number) is not True:
        raise ValidationError(f"ligne {line_number}: accélération AES désactivée")
    if _exact_type(record, "sha_hardware_acceleration", bool, line_number) is not True:
        raise ValidationError(f"ligne {line_number}: accélération SHA désactivée")
    if _integer(record, "flash_size_mb", line_number) != FLASH_SIZE_MB:
        raise ValidationError(
            f"ligne {line_number}: flash_size_mb doit valoir {FLASH_SIZE_MB}"
        )
    for field in ("app_elf_sha256", "sdkconfig_sha256"):
        if HEX_SHA256.fullmatch(_string(record, field, line_number)) is None:
            raise ValidationError(
                f"ligne {line_number}: {field} doit être un SHA-256 hexadécimal"
            )

    algorithms = set(ALGORITHM_OPERATIONS)
    if chacha_enabled:
        algorithms.add(CHACHA_ALGORITHM)
    context = {
        "chip_revision": chip_revision,
        "benchmark_core": benchmark_core,
        "cpu_hz": cpu_hz,
        "iterations": iterations,
        "warmup_iterations": warmup_iterations,
        "payload_bytes": payload_bytes,
        "task_stack_bytes": task_stack_bytes,
    }
    return context, algorithms


def _validate_correctness(
    record: dict[str, object], line_number: int, expected_algorithms: set[str]
) -> str:
    _exact_fields(record, CORRECTNESS_FIELDS, line_number)
    _validate_envelope(record, line_number)
    if record["record"] != "correctness":
        raise ValidationError(
            f"ligne {line_number}: type d'enregistrement inattendu dans la phase de correction"
        )
    algorithm = _string(record, "algorithm", line_number)
    if algorithm not in expected_algorithms:
        raise ValidationError(
            f"ligne {line_number}: algorithme hors matrice: {algorithm}"
        )
    if _string(record, "status", line_number) != "pass":
        raise ValidationError(
            f"ligne {line_number}: la correction doit avoir le statut pass"
        )
    psa_status = _exact_type(record, "psa_status", int, line_number)
    if psa_status != PSA_SUCCESS:
        raise ValidationError(
            f"ligne {line_number}: la correction doit retourner PSA_SUCCESS"
        )
    return algorithm


def _validate_measurement(
    record: dict[str, object],
    line_number: int,
    context: dict[str, int],
    expected_algorithms: set[str],
) -> str:
    _exact_fields(record, MEASUREMENT_FIELDS, line_number)
    _validate_envelope(record, line_number)
    if record["record"] != "measurement":
        raise ValidationError(
            f"ligne {line_number}: type d'enregistrement inattendu dans la phase de mesure"
        )
    algorithm = _string(record, "algorithm", line_number)
    if algorithm not in expected_algorithms:
        raise ValidationError(
            f"ligne {line_number}: algorithme hors matrice: {algorithm}"
        )

    operation, uses_payload = (
        ("import-encrypt-decrypt", True)
        if algorithm == CHACHA_ALGORITHM
        else ALGORITHM_OPERATIONS[algorithm]
    )
    if _string(record, "operation", line_number) != operation:
        raise ValidationError(
            f"ligne {line_number}: opération incohérente pour {algorithm}"
        )
    if _string(record, "status", line_number) != "pass":
        raise ValidationError(
            f"ligne {line_number}: la mesure doit avoir le statut pass"
        )

    attempts = _integer(record, "attempts", line_number, minimum=1)
    valid_samples = _integer(record, "valid_samples", line_number, minimum=1)
    if attempts != context["iterations"]:
        raise ValidationError(
            f"ligne {line_number}: attempts diffère des iterations annoncées"
        )
    if valid_samples != attempts:
        raise ValidationError(
            f"ligne {line_number}: valid_samples doit être égal à attempts"
        )
    expected_payload = context["payload_bytes"] if uses_payload else 0
    if _integer(record, "payload_bytes", line_number) != expected_payload:
        raise ValidationError(
            f"ligne {line_number}: payload_bytes incohérent pour {algorithm}"
        )
    if _integer(record, "benchmark_core", line_number) != context["benchmark_core"]:
        raise ValidationError(
            f"ligne {line_number}: benchmark_core diffère des métadonnées"
        )

    cycles = tuple(
        _integer(record, field, line_number, minimum=1)
        for field in ("cycles_min", "cycles_median", "cycles_p95", "cycles_max")
    )
    if cycles != tuple(sorted(cycles)):
        raise ValidationError(f"ligne {line_number}: ordre des cycles invalide")
    latency_fields = (
        "latency_ns_min",
        "latency_ns_median",
        "latency_ns_p95",
        "latency_ns_max",
    )
    latencies = tuple(
        _integer(record, field, line_number, minimum=1) for field in latency_fields
    )
    expected_latencies = tuple(
        cycles_value * 1_000_000_000 // context["cpu_hz"] for cycles_value in cycles
    )
    if latencies != expected_latencies:
        raise ValidationError(
            f"ligne {line_number}: latence non dérivée exactement des cycles"
        )

    heap_before = _integer(record, "heap_before_bytes", line_number)
    heap_min = _integer(record, "heap_min_bytes", line_number)
    heap_delta = _integer(record, "heap_delta_bytes", line_number)
    if heap_before < heap_min or heap_delta != heap_before - heap_min:
        raise ValidationError(f"ligne {line_number}: invariants heap invalides")
    stack_high_water = _integer(
        record, "stack_high_water_bytes", line_number, minimum=1
    )
    if stack_high_water > context["task_stack_bytes"]:
        raise ValidationError(
            f"ligne {line_number}: stack_high_water_bytes dépasse la stack allouée"
        )
    return algorithm


def validate_stream(stream: TextIO) -> ValidationSummary:
    records = _json_records(stream)
    metadata_line, metadata = records[0]
    context, expected_algorithms = _validate_metadata(metadata, metadata_line)
    correctness_algorithms: set[str] = set()
    measurement_algorithms: set[str] = set()
    measurement_phase = False

    for line_number, record in records[1:]:
        record_type = record.get("record")
        if record_type == "correctness":
            if measurement_phase:
                raise ValidationError(
                    f"ligne {line_number}: correction après le début de la phase de mesure"
                )
            algorithm = _validate_correctness(record, line_number, expected_algorithms)
            if algorithm in correctness_algorithms:
                raise ValidationError(
                    f"ligne {line_number}: correction dupliquée pour {algorithm}"
                )
            correctness_algorithms.add(algorithm)
        elif record_type == "measurement":
            measurement_phase = True
            algorithm = _validate_measurement(
                record, line_number, context, expected_algorithms
            )
            if algorithm not in correctness_algorithms:
                raise ValidationError(
                    f"ligne {line_number}: mesure avant correction pour {algorithm}"
                )
            if algorithm in measurement_algorithms:
                raise ValidationError(
                    f"ligne {line_number}: mesure dupliquée pour {algorithm}"
                )
            measurement_algorithms.add(algorithm)
        else:
            raise ValidationError(f"ligne {line_number}: type d'enregistrement inconnu")

    if (
        correctness_algorithms != expected_algorithms
        or measurement_algorithms != expected_algorithms
    ):
        raise ValidationError(
            "matrice exacte absente: "
            f"correction={sorted(correctness_algorithms)}, mesure={sorted(measurement_algorithms)}, "
            f"attendu={sorted(expected_algorithms)}"
        )
    return ValidationSummary(
        1, len(correctness_algorithms), len(measurement_algorithms)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input", type=Path, help="capture série contenant les lignes JSONL"
    )
    arguments = parser.parse_args()
    try:
        with arguments.input.open(encoding="utf-8") as stream:
            summary = validate_stream(stream)
    except (OSError, ValidationError) as error:
        print(f"ERREUR: {error}", file=sys.stderr)
        return 1
    print(
        "JSONL valide: "
        f"metadata={summary.metadata_records}, correctness={summary.correctness_records}, "
        f"measurement={summary.measurement_records}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
