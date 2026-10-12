#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "jsonl.h"

static void test_metadata_contract(void) {
    char                       buffer[1536];
    const benchmark_metadata_t metadata = {
        .idf_version               = "v6.0.2",
        .target                    = "esp32s3",
        .profile_id                = "baseline",
        .chip_model                = "esp32-s3",
        .chip_revision             = 1,
        .chip_cores                = 2,
        .benchmark_core            = 1,
        .cpu_hz                    = 240000000,
        .iterations                = 32,
        .warmup_iterations         = 3,
        .payload_bytes             = 1024,
        .task_stack_bytes          = 16384,
        .optimization              = "performance",
        .aes_hardware_acceleration = true,
        .sha_hardware_acceleration = true,
        .flash_size_mb             = 8,
        .app_elf_sha256            = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .sdkconfig_sha256          = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        .chacha20_poly1305_enabled = false,
    };

    assert(benchmark_jsonl_metadata(buffer, sizeof(buffer), &metadata) > 0);
    assert(strcmp(buffer,
                  "{\"schema\":\"cryptose.benchmark.v2\",\"record\":\"metadata\",\"idf_version\":\"v6.0.2\","
                  "\"target\":\"esp32s3\",\"profile_id\":\"baseline\",\"chip_model\":\"esp32-s3\","
                  "\"chip_revision\":1,\"chip_cores\":2,\"benchmark_core\":1,\"cpu_hz\":240000000,"
                  "\"iterations\":32,\"warmup_iterations\":3,\"payload_bytes\":1024,"
                  "\"task_stack_bytes\":16384,\"optimization\":\"performance\","
                  "\"aes_hardware_acceleration\":true,\"sha_hardware_acceleration\":true,\"flash_size_mb\":8,"
                  "\"app_elf_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
                  "\"sdkconfig_sha256\":\"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\","
                  "\"chacha20_poly1305_enabled\":false}") == 0);
}

static void test_correctness_contract(void) {
    char                          buffer[384];
    const benchmark_correctness_t result = {
        .algorithm  = "aes-256-gcm",
        .status     = "pass",
        .psa_status = 0,
    };

    assert(benchmark_jsonl_correctness(buffer, sizeof(buffer), &result) > 0);
    assert(strcmp(buffer,
                  "{\"schema\":\"cryptose.benchmark.v2\",\"record\":\"correctness\","
                  "\"algorithm\":\"aes-256-gcm\",\"status\":\"pass\",\"psa_status\":0}") == 0);
}

static void test_measurement_contract(void) {
    char                          buffer[1536];
    const benchmark_measurement_t result = {
        .algorithm              = "sha-256",
        .operation              = "hash",
        .status                 = "pass",
        .attempts               = 32,
        .valid_samples          = 32,
        .payload_bytes          = 1024,
        .benchmark_core         = 1,
        .cycles_min             = 2400,
        .cycles_median          = 4800,
        .cycles_p95             = 7200,
        .cycles_max             = 9600,
        .latency_ns_min         = 10000,
        .latency_ns_median      = 20000,
        .latency_ns_p95         = 30000,
        .latency_ns_max         = 40000,
        .heap_before_bytes      = 280000,
        .heap_min_bytes         = 279000,
        .heap_delta_bytes       = 1000,
        .stack_high_water_bytes = 4096,
    };

    assert(benchmark_jsonl_measurement(buffer, sizeof(buffer), &result) > 0);
    assert(strcmp(buffer,
                  "{\"schema\":\"cryptose.benchmark.v2\",\"record\":\"measurement\","
                  "\"algorithm\":\"sha-256\",\"operation\":\"hash\",\"status\":\"pass\","
                  "\"attempts\":32,\"valid_samples\":32,\"payload_bytes\":1024,\"benchmark_core\":1,"
                  "\"cycles_min\":2400,\"cycles_median\":4800,\"cycles_p95\":7200,\"cycles_max\":9600,"
                  "\"latency_ns_min\":10000,\"latency_ns_median\":20000,\"latency_ns_p95\":30000,"
                  "\"latency_ns_max\":40000,\"heap_before_bytes\":280000,\"heap_min_bytes\":279000,"
                  "\"heap_delta_bytes\":1000,\"stack_high_water_bytes\":4096}") == 0);
}

static void test_truncation_is_reported(void) {
    char                          buffer[16];
    const benchmark_correctness_t result = {
        .algorithm  = "aes-256-gcm",
        .status     = "pass",
        .psa_status = 0,
    };

    assert(benchmark_jsonl_correctness(buffer, sizeof(buffer), &result) < 0);
}

int main(void) {
    test_metadata_contract();
    test_correctness_contract();
    test_measurement_contract();
    test_truncation_is_reported();
    puts("jsonl contract: OK");
    return 0;
}
