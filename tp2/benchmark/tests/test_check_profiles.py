import unittest

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from check_profiles import ProfileDifferenceError, validate_profile_difference


BASELINE = """\
CONFIG_CRYPTOSE_PROFILE_ID="baseline"
# CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305 is not set
# CONFIG_MBEDTLS_CHACHA20_C is not set
# CONFIG_MBEDTLS_CHACHAPOLY_C is not set
CONFIG_MBEDTLS_HARDWARE_AES=y
"""

CHACHA = """\
CONFIG_CRYPTOSE_PROFILE_ID="chacha20-poly1305"
CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305=y
CONFIG_MBEDTLS_CHACHA20_C=y
CONFIG_MBEDTLS_CHACHAPOLY_C=y
CONFIG_MBEDTLS_HARDWARE_AES=y
"""


class CheckProfilesTests(unittest.TestCase):
    def test_accepts_only_the_expected_chacha_delta(self) -> None:
        validate_profile_difference(BASELINE, CHACHA)

    def test_rejects_an_unrelated_effective_delta(self) -> None:
        changed = CHACHA.replace(
            "CONFIG_MBEDTLS_HARDWARE_AES=y", "# CONFIG_MBEDTLS_HARDWARE_AES is not set"
        )
        with self.assertRaisesRegex(ProfileDifferenceError, "MBEDTLS_HARDWARE_AES"):
            validate_profile_difference(BASELINE, changed)

    def test_rejects_a_missing_expected_delta(self) -> None:
        changed = CHACHA.replace(
            "CONFIG_MBEDTLS_CHACHAPOLY_C=y", "# CONFIG_MBEDTLS_CHACHAPOLY_C is not set"
        )
        with self.assertRaisesRegex(ProfileDifferenceError, "CHACHAPOLY"):
            validate_profile_difference(BASELINE, changed)


if __name__ == "__main__":
    unittest.main()
