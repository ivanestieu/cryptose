#include "jsonl.h"

#include <inttypes.h>
#include <stdio.h>

static int checked_result(char* destination, size_t capacity, int written) {
    if (destination == NULL || capacity == 0 || written < 0 || (size_t) written >= capacity) {
        if (destination != NULL && capacity > 0) {
            destination[capacity - 1] = '\0';
        }
        return -1;
    }
    return written;
}

int benchmark_jsonl_metadata(char* destination, size_t capacity, const benchmark_metadata_t* metadata) {
    if (metadata == NULL || metadata->idf_version == NULL || metadata->target == NULL || metadata->profile_id == NULL ||
        metadata->chip_model == NULL || metadata->optimization == NULL || metadata->app_elf_sha256 == NULL ||
        metadata->sdkconfig_sha256 == NULL) {
        return -1;
    }

    const int written = snprintf(
        destination, capacity,
        "{\"schema\":\"%s\",\"record\":\"metadata\",\"idf_version\":\"%s\",\"target\":\"%s\","
        "\"profile_id\":\"%s\",\"chip_model\":\"%s\",\"chip_revision\":%" PRIu16 ",\"chip_cores\":%" PRIu8
        ",\"benchmark_core\":%" PRIu32 ",\"cpu_hz\":%" PRIu32 ",\"iterations\":%" PRIu32
        ",\"warmup_iterations\":%" PRIu32
        ",\"payload_bytes\":%zu,\"task_stack_bytes\":%zu,\"optimization\":\"%s\","
        "\"aes_hardware_acceleration\":%s,\"sha_hardware_acceleration\":%s,\"flash_size_mb\":%" PRIu32
        ",\"app_elf_sha256\":\"%s\",\"sdkconfig_sha256\":\"%s\",\"chacha20_poly1305_enabled\":%s}",
        CRYPTOSE_BENCHMARK_SCHEMA, metadata->idf_version, metadata->target, metadata->profile_id, metadata->chip_model,
        metadata->chip_revision, metadata->chip_cores, metadata->benchmark_core, metadata->cpu_hz, metadata->iterations,
        metadata->warmup_iterations, metadata->payload_bytes, metadata->task_stack_bytes, metadata->optimization,
        metadata->aes_hardware_acceleration ? "true" : "false", metadata->sha_hardware_acceleration ? "true" : "false",
        metadata->flash_size_mb, metadata->app_elf_sha256, metadata->sdkconfig_sha256,
        metadata->chacha20_poly1305_enabled ? "true" : "false");
    return checked_result(destination, capacity, written);
}

int benchmark_jsonl_correctness(char* destination, size_t capacity, const benchmark_correctness_t* result) {
    if (result == NULL || result->algorithm == NULL || result->status == NULL) {
        return -1;
    }

    const int written = snprintf(destination, capacity,
                                 "{\"schema\":\"%s\",\"record\":\"correctness\",\"algorithm\":\"%s\","
                                 "\"status\":\"%s\",\"psa_status\":%" PRId32 "}",
                                 CRYPTOSE_BENCHMARK_SCHEMA, result->algorithm, result->status, result->psa_status);
    return checked_result(destination, capacity, written);
}

int benchmark_jsonl_measurement(char* destination, size_t capacity, const benchmark_measurement_t* result) {
    if (result == NULL || result->algorithm == NULL || result->operation == NULL || result->status == NULL) {
        return -1;
    }

    const int written = snprintf(
        destination, capacity,
        "{\"schema\":\"%s\",\"record\":\"measurement\",\"algorithm\":\"%s\",\"operation\":\"%s\","
        "\"status\":\"%s\",\"attempts\":%" PRIu32 ",\"valid_samples\":%" PRIu32
        ",\"payload_bytes\":%zu,\"benchmark_core\":%" PRIu32 ",\"cycles_min\":%" PRIu64 ",\"cycles_median\":%" PRIu64
        ",\"cycles_p95\":%" PRIu64 ",\"cycles_max\":%" PRIu64 ",\"latency_ns_min\":%" PRIu64
        ",\"latency_ns_median\":%" PRIu64 ",\"latency_ns_p95\":%" PRIu64 ",\"latency_ns_max\":%" PRIu64
        ",\"heap_before_bytes\":%zu,\"heap_min_bytes\":%zu,\"heap_delta_bytes\":%zu,"
        "\"stack_high_water_bytes\":%zu}",
        CRYPTOSE_BENCHMARK_SCHEMA, result->algorithm, result->operation, result->status, result->attempts,
        result->valid_samples, result->payload_bytes, result->benchmark_core, result->cycles_min, result->cycles_median,
        result->cycles_p95, result->cycles_max, result->latency_ns_min, result->latency_ns_median,
        result->latency_ns_p95, result->latency_ns_max, result->heap_before_bytes, result->heap_min_bytes,
        result->heap_delta_bytes, result->stack_high_water_bytes);
    return checked_result(destination, capacity, written);
}
