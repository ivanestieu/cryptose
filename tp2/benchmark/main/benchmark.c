#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto_cases.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "jsonl.h"
#include "measure.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

#define JSONL_BUFFER_BYTES 1536

_Static_assert(CONFIG_APP_RETRIEVE_LEN_ELF_SHA == 64, "A full application ELF SHA-256 digest is required");

#ifndef CRYPTOSE_SDKCONFIG_SHA256
#    error "CRYPTOSE_SDKCONFIG_SHA256 must be injected by CMake"
#endif

#ifdef CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305
#    define CHACHA20_POLY1305_ENABLED true
#else
#    define CHACHA20_POLY1305_ENABLED false
#endif

#ifdef CONFIG_MBEDTLS_HARDWARE_AES
#    define AES_HARDWARE_ACCELERATION true
#else
#    define AES_HARDWARE_ACCELERATION false
#endif

#ifdef CONFIG_MBEDTLS_HARDWARE_SHA
#    define SHA_HARDWARE_ACCELERATION true
#else
#    define SHA_HARDWARE_ACCELERATION false
#endif

#ifdef CONFIG_COMPILER_OPTIMIZATION_PERF
#    define OPTIMIZATION_PROFILE "performance"
#else
#    define OPTIMIZATION_PROFILE "other"
#endif

#if CONFIG_ESPTOOLPY_FLASHSIZE_4MB
#    define FLASH_SIZE_MB 4
#elif CONFIG_ESPTOOLPY_FLASHSIZE_8MB
#    define FLASH_SIZE_MB 8
#else
#    define FLASH_SIZE_MB 0
#endif

static bool emit_line(int result, const char* buffer) {
    if (result >= 0) {
        puts(buffer);
        return true;
    } else {
        puts("{\"schema\":\"cryptose.benchmark.v2\",\"record\":\"error\",\"status\":\"serialization-error\"}");
        return false;
    }
}

static const char* chip_model_name(esp_chip_model_t model) {
    switch (model) {
        case CHIP_ESP32: return "esp32";
        case CHIP_ESP32S3: return "esp32-s3";
        default: return "unknown";
    }
}

static bool emit_metadata(void) {
    char            buffer[JSONL_BUFFER_BYTES];
    char            app_elf_sha256[65] = {0};
    esp_chip_info_t chip_info          = {0};
    esp_chip_info(&chip_info);
    const size_t app_elf_sha256_length = esp_app_get_elf_sha256(app_elf_sha256, sizeof(app_elf_sha256));
    if (app_elf_sha256_length != sizeof(app_elf_sha256) || strlen(app_elf_sha256) != 64) {
        puts("{\"schema\":\"cryptose.benchmark.v2\",\"record\":\"error\",\"status\":\"app-digest-error\"}");
        return false;
    }

    const benchmark_metadata_t metadata = {
        .idf_version               = esp_get_idf_version(),
        .target                    = CONFIG_IDF_TARGET,
        .profile_id                = CONFIG_CRYPTOSE_PROFILE_ID,
        .chip_model                = chip_model_name(chip_info.model),
        .chip_revision             = chip_info.revision,
        .chip_cores                = chip_info.cores,
        .benchmark_core            = CONFIG_CRYPTOSE_BENCHMARK_CORE,
        .cpu_hz                    = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * 1000000U,
        .iterations                = CONFIG_CRYPTOSE_BENCHMARK_ITERATIONS,
        .warmup_iterations         = CONFIG_CRYPTOSE_BENCHMARK_WARMUP_ITERATIONS,
        .payload_bytes             = CONFIG_CRYPTOSE_BENCHMARK_PAYLOAD_BYTES,
        .task_stack_bytes          = CONFIG_CRYPTOSE_BENCHMARK_TASK_STACK_BYTES,
        .optimization              = OPTIMIZATION_PROFILE,
        .aes_hardware_acceleration = AES_HARDWARE_ACCELERATION,
        .sha_hardware_acceleration = SHA_HARDWARE_ACCELERATION,
        .flash_size_mb             = FLASH_SIZE_MB,
        .app_elf_sha256            = app_elf_sha256,
        .sdkconfig_sha256          = CRYPTOSE_SDKCONFIG_SHA256,
        .chacha20_poly1305_enabled = CHACHA20_POLY1305_ENABLED,
    };
    return emit_line(benchmark_jsonl_metadata(buffer, sizeof(buffer), &metadata), buffer);
}

static void emit_correctness(const crypto_case_t* test_case, psa_status_t status) {
    char                          buffer[JSONL_BUFFER_BYTES];
    const benchmark_correctness_t result = {
        .algorithm  = test_case->algorithm,
        .status     = status == PSA_SUCCESS ? "pass" : "fail",
        .psa_status = status,
    };
    emit_line(benchmark_jsonl_correctness(buffer, sizeof(buffer), &result), buffer);
}

static void emit_measurement(const benchmark_measurement_t* measurement) {
    char buffer[JSONL_BUFFER_BYTES];
    emit_line(benchmark_jsonl_measurement(buffer, sizeof(buffer), measurement), buffer);
}

void app_main(void) {
    if (! emit_metadata()) {
        return;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return;
    }
    crypto_cases_prepare_payload();

    size_t               case_count = 0;
    const crypto_case_t* cases      = crypto_cases_get(&case_count);
    bool                 all_valid  = true;
    for (size_t index = 0; index < case_count; ++index) {
        const psa_status_t status = cases[index].verify();
        emit_correctness(&cases[index], status);
        all_valid = all_valid && status == PSA_SUCCESS;
    }
    if (! all_valid) {
        return;
    }

    for (size_t index = 0; index < case_count; ++index) {
        const benchmark_measurement_t measurement = benchmark_measure_case(&cases[index]);
        emit_measurement(&measurement);
    }
}
