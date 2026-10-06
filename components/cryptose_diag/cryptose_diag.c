#include "cryptose_diag.h"

#include <inttypes.h>

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "cryptose_diag";

esp_err_t cryptose_diag_capture(cryptose_diag_snapshot_t* snapshot) {
    if (snapshot == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);

    uint32_t        flash_size   = 0;
    const esp_err_t flash_result = esp_flash_get_size(NULL, &flash_size);
    if (flash_result != ESP_OK) {
        return flash_result;
    }

    snapshot->idf_version             = esp_get_idf_version();
    snapshot->flash_size_bytes        = flash_size;
    snapshot->free_heap_bytes         = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    snapshot->minimum_free_heap_bytes = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    snapshot->stack_high_water_bytes  = uxTaskGetStackHighWaterMark(NULL);
    snapshot->cpu_cores               = chip_info.cores;
    snapshot->chip_revision_major     = chip_info.revision / 100;
    snapshot->chip_revision_minor     = chip_info.revision % 100;
    snapshot->has_wifi                = (chip_info.features & CHIP_FEATURE_WIFI_BGN) != 0;
    snapshot->has_bluetooth_le        = (chip_info.features & CHIP_FEATURE_BLE) != 0;
    return ESP_OK;
}

void cryptose_diag_log(const cryptose_diag_snapshot_t* snapshot, unsigned sample) {
    if (snapshot == NULL) {
        ESP_LOGE(TAG, "cannot log a null snapshot");
        return;
    }

    ESP_LOGI(TAG,
             "sample=%u idf=%s cores=%u revision=%u.%u flash=%" PRIu32
             " free_heap=%zu minimum_free_heap=%zu stack_high_water=%zu wifi=%d ble=%d",
             sample, snapshot->idf_version, snapshot->cpu_cores, snapshot->chip_revision_major,
             snapshot->chip_revision_minor, snapshot->flash_size_bytes, snapshot->free_heap_bytes,
             snapshot->minimum_free_heap_bytes, snapshot->stack_high_water_bytes, snapshot->has_wifi,
             snapshot->has_bluetooth_le);
}
