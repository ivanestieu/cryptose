#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t minimum;
    uint32_t median;
    uint32_t p95;
    uint32_t maximum;
} benchmark_cycle_statistics_t;

bool benchmark_statistics_compute(uint32_t* samples, size_t count, benchmark_cycle_statistics_t* statistics);
