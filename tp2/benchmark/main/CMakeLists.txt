idf_component_register(
    SRCS "benchmark.c" "crypto_cases.c" "jsonl.c" "measure.c" "statistics.c"
    INCLUDE_DIRS "."
    REQUIRES esp_app_format esp_common esp_hw_support freertos heap mbedtls
)

idf_build_get_property(sdkconfig_path SDKCONFIG)
file(SHA256 "${sdkconfig_path}" sdkconfig_sha256)
target_compile_definitions(${COMPONENT_LIB} PRIVATE CRYPTOSE_SDKCONFIG_SHA256="${sdkconfig_sha256}")
