"""Progress check: every TODO_STUDENT you complete removes one failure here.

The real acceptance test runs on the board: the correctness phase (known-answer vectors)
and validate_jsonl.py on your captures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[1]
STUDENT_FILES = (
    "main/statistics.c",
    "main/crypto_cases.c",
    "main/measure.c",
    "tools/analyze_results.py",
)


@pytest.mark.parametrize("relative", STUDENT_FILES)
def test_no_todo_left(relative: str) -> None:
    source = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
    remaining = source.count("TODO_STUDENT")
    assert remaining == 0, f"{relative}: {remaining} TODO_STUDENT restant(s)"
