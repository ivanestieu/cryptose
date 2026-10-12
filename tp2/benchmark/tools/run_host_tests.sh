#!/usr/bin/env bash
# Host tests (statistics, JSONL, validator, analysis) in a clean environment: an activated
# ESP-IDF shell puts its ULP `ld` and its own python3 first on PATH, which breaks both CMake
# and pytest (issue #8). Usage, from the project root: tools/run_host_tests.sh
set -u
cd "$(dirname "$0")/.."
exec env -i HOME="$HOME" PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 bash -c '
status=0
cmake -S tests -B build-host -G Ninja >/dev/null && cmake --build build-host >/dev/null \
  && ctest --test-dir build-host --output-on-failure || status=1
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests || status=1
exit $status'
