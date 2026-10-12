#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "cryptose_diag.h"
#include "esp_log.h"

static const char* TAG = "tutorial";

static void diagnostic_task(void* context) {
    (void) context;

    for (unsigned sample = 0; sample < 3; ++sample) {
        cryptose_diag_snapshot_t snapshot;
        const esp_err_t          result = cryptose_diag_capture(&snapshot);
        if (result != ESP_OK) {
            ESP_LOGE(TAG, "diagnostic capture failed: %s", esp_err_to_name(result));
            vTaskDelete(NULL);
            return;
        }

        cryptose_diag_log(&snapshot, sample);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_CRYPTOSE_DIAG_PERIOD_MS));
    }

    ESP_LOGI(TAG, "CRYPTOSE_TUTORIAL_READY");
    vTaskDelete(NULL);
}

void app_main(void) {
    ESP_LOGI(TAG, "stage=boot target=%s", CONFIG_IDF_TARGET);

    const BaseType_t created = xTaskCreate(diagnostic_task, "cryptose_diag", 3072, NULL, tskIDLE_PRIORITY + 1, NULL);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "unable to create diagnostic task");
    }
}
