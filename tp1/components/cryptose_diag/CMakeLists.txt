idf_component_register(
    SRCS "cryptose_diag.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_common esp_hw_support esp_system freertos heap log spi_flash
)
