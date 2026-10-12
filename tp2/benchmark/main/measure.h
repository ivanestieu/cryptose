#pragma once

#include "crypto_cases.h"
#include "jsonl.h"

/*
 * Runs one case in a dedicated task pinned to CONFIG_CRYPTOSE_BENCHMARK_CORE: warm-up,
 * CONFIG_CRYPTOSE_BENCHMARK_ITERATIONS timed executions, then cycle statistics, heap
 * pressure and stack high-water mark. Blocks until the task has finished.
 */
benchmark_measurement_t benchmark_measure_case(const crypto_case_t* test_case);
