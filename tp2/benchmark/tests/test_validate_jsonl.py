import copy
import io
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from validate_jsonl import ValidationError, validate_stream


OPERATIONS = {
    "aes-256-gcm": ("import-encrypt-decrypt", 1024),
    "sha-256": ("hash", 1024),
    "hmac-sha-256": ("import-mac", 1024),
    "ecdh-p256": ("two-keygen-two-agreements", 0),
    "x25519": ("two-keygen-two-agreements", 0),
    "ecdsa-p256-sha-256": ("hash-keygen-sign-verify", 1024),
}


def valid_records(
    *, chacha: bool = False, target: str = "esp32s3", chip_model: str = "esp32-s3"
) -> list[dict[str, object]]:
    profile_id = "chacha20-poly1305" if chacha else "baseline"
    metadata: dict[str, object] = {
        "schema": "cryptose.benchmark.v2",
        "record": "metadata",
        "idf_version": "v6.0.3",
        "target": target,
        "profile_id": profile_id,
        "chip_model": chip_model,
        "chip_revision": 1,
        "chip_cores": 2,
        "benchmark_core": 1,
        "cpu_hz": 240_000_000,
        "iterations": 32,
        "warmup_iterations": 2,
        "payload_bytes": 1024,
        "task_stack_bytes": 16_384,
        "optimization": "performance",
        "aes_hardware_acceleration": True,
        "sha_hardware_acceleration": True,
        "flash_size_mb": 4,
        "app_elf_sha256": "a" * 64,
        "sdkconfig_sha256": "b" * 64,
        "chacha20_poly1305_enabled": chacha,
    }
    operations = dict(OPERATIONS)
    if chacha:
        operations["chacha20-poly1305"] = ("import-encrypt-decrypt", 1024)

    records = [metadata]
    records.extend(
        {
            "schema": "cryptose.benchmark.v2",
            "record": "correctness",
            "algorithm": algorithm,
            "status": "pass",
            "psa_status": 0,
        }
        for algorithm in operations
    )
    records.extend(
        {
            "schema": "cryptose.benchmark.v2",
            "record": "measurement",
            "algorithm": algorithm,
            "operation": operation,
            "status": "pass",
            "attempts": 32,
            "valid_samples": 32,
            "payload_bytes": payload_bytes,
            "benchmark_core": 1,
            "cycles_min": 2400,
            "cycles_median": 4800,
            "cycles_p95": 7200,
            "cycles_max": 9600,
            "latency_ns_min": 10_000,
            "latency_ns_median": 20_000,
            "latency_ns_p95": 30_000,
            "latency_ns_max": 40_000,
            "heap_before_bytes": 280_000,
            "heap_min_bytes": 279_000,
            "heap_delta_bytes": 1000,
            "stack_high_water_bytes": 4096,
        }
        for algorithm, (operation, payload_bytes) in operations.items()
    )
    return records


def document(records: list[dict[str, object]]) -> str:
    return "\n".join(json.dumps(record, separators=(",", ":")) for record in records)


class ValidateJsonlTests(unittest.TestCase):
    def test_accepts_esp_idf_603_capture(self) -> None:
        records = valid_records()
        records[0]["idf_version"] = "v6.0.3"
        validate_stream(io.StringIO(document(records)))

    def test_rejects_previous_esp_idf_version(self) -> None:
        records = valid_records()
        records[0]["idf_version"] = "v6.0.2"
        with self.assertRaisesRegex(ValidationError, "version ESP-IDF"):
            validate_stream(io.StringIO(document(records)))

    def test_version_pin_is_read_from_repackaged_course_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ESP_IDF_VERSION").write_text("6.0.4\n", encoding="utf-8")
            with patch(
                "validate_jsonl.__file__",
                str(root / "benchmark/tools/validate_jsonl.py"),
            ):
                records = valid_records()
                records[0]["idf_version"] = "v6.0.4"
                validate_stream(io.StringIO(document(records)))

    def test_rejects_capture_when_course_version_pin_is_missing(self) -> None:
        with TemporaryDirectory() as directory:
            with patch(
                "validate_jsonl.__file__",
                str(Path(directory) / "tools/validate_jsonl.py"),
            ):
                with self.assertRaisesRegex(
                    ValidationError, "ESP_IDF_VERSION introuvable"
                ):
                    validate_stream(io.StringIO(document(valid_records())))

    def test_accepts_exact_baseline_and_chacha_matrices(self) -> None:
        baseline = validate_stream(io.StringIO(document(valid_records())))
        chacha = validate_stream(io.StringIO(document(valid_records(chacha=True))))
        self.assertEqual(
            (baseline.correctness_records, baseline.measurement_records), (6, 6)
        )
        self.assertEqual(
            (chacha.correctness_records, chacha.measurement_records), (7, 7)
        )

    def test_rejects_unknown_fields_for_every_record_type(self) -> None:
        for index in (0, 1, 7):
            with self.subTest(index=index):
                records = valid_records()
                records[index]["unexpected"] = 1
                with self.assertRaisesRegex(ValidationError, "champs inconnus"):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_missing_fields_for_every_record_type(self) -> None:
        for index, field in (
            (0, "sdkconfig_sha256"),
            (1, "psa_status"),
            (7, "cycles_p95"),
        ):
            with self.subTest(index=index, field=field):
                records = valid_records()
                del records[index][field]
                with self.assertRaisesRegex(ValidationError, "champs manquants"):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_nested_or_wrong_scalar_types(self) -> None:
        for index, field, value in (
            (0, "idf_version", ["v6.0.2"]),
            (0, "iterations", True),
            (0, "chip_revision", -1),
            (0, "app_elf_sha256", {"digest": "a" * 64}),
            (1, "psa_status", False),
            (7, "cycles_min", "2400"),
        ):
            with self.subTest(index=index, field=field):
                records = valid_records()
                records[index][field] = value
                with self.assertRaises(ValidationError):
                    validate_stream(io.StringIO(document(records)))

    def test_accepts_every_target_of_the_course_fleet(self) -> None:
        for target, chip_model in (("esp32", "esp32"), ("esp32s3", "esp32-s3")):
            with self.subTest(target=target):
                records = valid_records(target=target, chip_model=chip_model)
                summary = validate_stream(io.StringIO(document(records)))
                self.assertEqual(summary.metadata_records, 1)

    def test_rejects_a_chip_model_that_contradicts_the_target(self) -> None:
        records = valid_records(target="esp32", chip_model="esp32-s3")
        with self.assertRaises(ValidationError):
            validate_stream(io.StringIO(document(records)))

    def test_rejects_non_reproducible_metadata_values(self) -> None:
        mutations = (
            ("idf_version", "v6.1.0"),
            ("target", "esp32c3"),
            ("chip_model", "esp32"),
            ("profile_id", "custom"),
            ("chip_cores", 1),
            ("cpu_hz", 160_000_000),
            ("iterations", 257),
            ("warmup_iterations", 0),
            ("payload_bytes", 8),
            ("task_stack_bytes", 0),
            ("optimization", "size"),
            ("aes_hardware_acceleration", False),
            ("sha_hardware_acceleration", False),
            ("flash_size_mb", 2),
            ("flash_size_mb", 8),
            ("app_elf_sha256", "not-a-digest"),
            ("sdkconfig_sha256", "A" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                records = valid_records()
                records[0][field] = value
                with self.assertRaises(ValidationError):
                    validate_stream(io.StringIO(document(records)))

    def test_accepts_documented_metadata_boundaries(self) -> None:
        for field, values in (
            ("warmup_iterations", (1, 32)),
            ("payload_bytes", (16, 4096)),
            ("task_stack_bytes", (8192, 32768)),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    records = valid_records()
                    records[0][field] = value
                    if field == "payload_bytes":
                        for record in records:
                            if record.get("record") == "measurement" and record[
                                "algorithm"
                            ] not in {
                                "ecdh-p256",
                                "x25519",
                            }:
                                record["payload_bytes"] = value
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_metadata_values_outside_documented_bounds(self) -> None:
        for field, values in (
            ("warmup_iterations", (0, 33)),
            ("payload_bytes", (15, 4097)),
            ("task_stack_bytes", (8191, 32769)),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    records = valid_records()
                    records[0][field] = value
                    with self.assertRaisesRegex(ValidationError, field):
                        validate_stream(io.StringIO(document(records)))

    def test_rejects_watchdog_and_backtrace_diagnostics(self) -> None:
        valid = document(valid_records())
        for diagnostic in (
            "E (1234) task_wdt: Task watchdog got triggered",
            "Guru Meditation Error: Core 1 panic'ed\nBacktrace: 0x40000000:0x3fce0000",
        ):
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(ValidationError, "watchdog|backtrace"):
                    validate_stream(io.StringIO(f"{diagnostic}\n{valid}"))

    def test_rejects_failed_or_nonzero_correctness(self) -> None:
        for field, value in (("status", "fail"), ("psa_status", -149)):
            with self.subTest(field=field):
                records = valid_records()
                records[1][field] = value
                with self.assertRaisesRegex(ValidationError, "correction"):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_failed_measurement_and_wrong_operation(self) -> None:
        for field, value in (("status", "fail"), ("operation", "encrypt")):
            with self.subTest(field=field):
                records = valid_records()
                records[7][field] = value
                with self.assertRaisesRegex(ValidationError, "mesure|opération"):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_missing_extra_or_duplicate_algorithms(self) -> None:
        mutations = []
        missing = valid_records()
        del missing[1]
        mutations.append(missing)
        extra = valid_records()
        extra[1]["algorithm"] = "rsa-2048"
        mutations.append(extra)
        duplicate = valid_records()
        duplicate[2]["algorithm"] = duplicate[1]["algorithm"]
        mutations.append(duplicate)
        for index, records in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ValidationError, "matrice|dupliqué|mesure avant correction"
                ):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_profile_and_chacha_inconsistencies(self) -> None:
        for field, value in (
            ("profile_id", "chacha20-poly1305"),
            ("chacha20_poly1305_enabled", True),
        ):
            with self.subTest(field=field):
                records = valid_records()
                records[0][field] = value
                with self.assertRaisesRegex(ValidationError, "profil|matrice"):
                    validate_stream(io.StringIO(document(records)))

        records = valid_records(chacha=True)
        records = [
            record
            for record in records
            if record.get("algorithm") != "chacha20-poly1305"
        ]
        with self.assertRaisesRegex(ValidationError, "matrice"):
            validate_stream(io.StringIO(document(records)))

    def test_rejects_phase_order_violations(self) -> None:
        records = valid_records()
        records[1], records[7] = records[7], records[1]
        with self.assertRaisesRegex(ValidationError, "phase|correction"):
            validate_stream(io.StringIO(document(records)))

        records = valid_records()
        records[8] = copy.deepcopy(records[7])
        with self.assertRaisesRegex(ValidationError, "mesure dupliquée"):
            validate_stream(io.StringIO(document(records)))

    def test_rejects_attempt_sample_payload_and_core_mismatches(self) -> None:
        for field, value in (
            ("attempts", 31),
            ("valid_samples", 31),
            ("payload_bytes", 512),
            ("benchmark_core", 0),
        ):
            with self.subTest(field=field):
                records = valid_records()
                records[7][field] = value
                with self.assertRaisesRegex(ValidationError, field):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_cycle_order_and_latency_derivation_errors(self) -> None:
        records = valid_records()
        records[7]["cycles_p95"] = 2000
        with self.assertRaisesRegex(ValidationError, "cycles"):
            validate_stream(io.StringIO(document(records)))

        records = valid_records()
        records[7]["latency_ns_median"] = 20_001
        with self.assertRaisesRegex(ValidationError, "latence"):
            validate_stream(io.StringIO(document(records)))

    def test_rejects_heap_and_stack_invariant_errors(self) -> None:
        mutations = []
        negative_heap = valid_records()
        negative_heap[7]["heap_min_bytes"] = 281_000
        mutations.append((negative_heap, "heap"))
        bad_delta = valid_records()
        bad_delta[7]["heap_delta_bytes"] = 999
        mutations.append((bad_delta, "heap"))
        bad_stack = valid_records()
        bad_stack[7]["stack_high_water_bytes"] = 20_000
        mutations.append((bad_stack, "stack"))
        for records, pattern in mutations:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValidationError, pattern):
                    validate_stream(io.StringIO(document(records)))

    def test_rejects_unknown_record_and_malformed_json(self) -> None:
        records = valid_records()
        records[1]["record"] = "diagnostic"
        with self.assertRaisesRegex(ValidationError, "type d'enregistrement"):
            validate_stream(io.StringIO(document(records)))
        with self.assertRaisesRegex(ValidationError, "JSON invalide"):
            validate_stream(io.StringIO("{not-json}"))

    def test_rejects_non_scalar_secret_bearing_additions(self) -> None:
        records = copy.deepcopy(valid_records())
        records[1]["private_key"] = {"bytes": [1, 2, 3]}
        with self.assertRaisesRegex(ValidationError, "champs inconnus"):
            validate_stream(io.StringIO(document(records)))


if __name__ == "__main__":
    unittest.main()
