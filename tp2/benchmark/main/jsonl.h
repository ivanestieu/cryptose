#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTOSE_BENCHMARK_SCHEMA "cryptose.benchmark.v2"

typedef struct {
    const char* idf_version;
    const char* target;
    const char* profile_id;
    const char* chip_model;
    uint16_t    chip_revision;
    uint8_t     chip_cores;
    uint32_t    benchmark_core;
    uint32_t    cpu_hz;
    uint32_t    iterations;
    uint32_t    warmup_iterations;
    size_t      payload_bytes;
    size_t      task_stack_bytes;
    const char* optimization;
    bool        aes_hardware_acceleration;
    bool        sha_hardware_acceleration;
    uint32_t    flash_size_mb;
    const char* app_elf_sha256;
    const char* sdkconfig_sha256;
    bool        chacha20_poly1305_enabled;
} benchmark_metadata_t;

typedef struct {
    const char* algorithm;
    const char* status;
    int32_t     psa_status;
} benchmark_correctness_t;

typedef struct {
    const char* algorithm;
    const char* operation;
    const char* status;
    uint32_t    attempts;
    uint32_t    valid_samples;
    size_t      payload_bytes;
    uint32_t    benchmark_core;
    uint64_t    cycles_min;
    uint64_t    cycles_median;
    uint64_t    cycles_p95;
    uint64_t    cycles_max;
    uint64_t    latency_ns_min;
    uint64_t    latency_ns_median;
    uint64_t    latency_ns_p95;
    uint64_t    latency_ns_max;
    size_t      heap_before_bytes;
    size_t      heap_min_bytes;
    size_t      heap_delta_bytes;
    size_t      stack_high_water_bytes;
} benchmark_measurement_t;

int benchmark_jsonl_metadata(char* destination, size_t capacity, const benchmark_metadata_t* metadata);
int benchmark_jsonl_correctness(char* destination, size_t capacity, const benchmark_correctness_t* result);
int benchmark_jsonl_measurement(char* destination, size_t capacity, const benchmark_measurement_t* result);

#ifdef __cplusplus
}
#endif
