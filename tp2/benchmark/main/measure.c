#include "measure.h"

#include <stdbool.h>
#include <stdint.h>

#include "esp_cpu.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "statistics.h"

_Static_assert(sizeof(StackType_t) == 1, "ESP-IDF stack sizes and high-water marks must be expressed in bytes");

typedef struct {
    const crypto_case_t*    test_case;
    TaskHandle_t            parent;
    benchmark_measurement_t measurement;
} measurement_job_t;

__attribute__((unused)) static uint64_t cycles_to_nanoseconds(uint64_t cycles) {
    return (cycles * UINT64_C(1000000000)) / (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * UINT64_C(1000000));
}

/*
 * Body of the measurement task, pinned to CONFIG_CRYPTOSE_BENCHMARK_CORE. Fill job->measurement,
 * then wake the parent (xTaskNotifyGive) and delete this task, as the skeleton below does.
 *
 * Contract (the validator checks every point):
 *   1. CONFIG_CRYPTOSE_BENCHMARK_WARMUP_ITERATIONS untimed runs of job->test_case->execute();
 *   2. heap: start heap_caps_monitor_local_minimum_free_size_start(), read the free heap before,
 *      the local minimum after, then stop the monitor;
 *   3. CONFIG_CRYPTOSE_BENCHMARK_ITERATIONS timed runs: read esp_cpu_get_cycle_count() right
 *      before and right after execute(), keep the sample only if it returned PSA_SUCCESS, and
 *      yield (vTaskDelay(1)) OUTSIDE the timed window so the idle task and its watchdog run;
 *   4. statistics with benchmark_statistics_compute(), latencies with cycles_to_nanoseconds();
 *   5. status "pass" only if warm-up, heap monitor, statistics and all samples are valid;
 *   6. stack_high_water_bytes = uxTaskGetStackHighWaterMark(NULL).
 */
static void measurement_task(void* parameter) {
    measurement_job_t* job = parameter;

    /* TODO_STUDENT: warm-up, heap monitor, timed loop, statistics (see the contract above). */

    job->measurement = (benchmark_measurement_t) {
        .algorithm      = job->test_case->algorithm,
        .operation      = job->test_case->operation,
        .status         = "fail",
        .attempts       = CONFIG_CRYPTOSE_BENCHMARK_ITERATIONS,
        .payload_bytes  = job->test_case->payload_bytes,
        .benchmark_core = CONFIG_CRYPTOSE_BENCHMARK_CORE,
    };

    xTaskNotifyGive(job->parent);
    vTaskDelete(NULL);
}

benchmark_measurement_t benchmark_measure_case(const crypto_case_t* test_case) {
    measurement_job_t job = {
        .test_case = test_case,
        .parent    = xTaskGetCurrentTaskHandle(),
    };

    const BaseType_t created =
        xTaskCreatePinnedToCore(measurement_task, "crypto-benchmark", CONFIG_CRYPTOSE_BENCHMARK_TASK_STACK_BYTES, &job,
                                tskIDLE_PRIORITY + 2, NULL, CONFIG_CRYPTOSE_BENCHMARK_CORE);
    if (created != pdPASS) {
        return (benchmark_measurement_t) {
            .algorithm      = test_case->algorithm,
            .operation      = test_case->operation,
            .status         = "fail",
            .attempts       = CONFIG_CRYPTOSE_BENCHMARK_ITERATIONS,
            .payload_bytes  = test_case->payload_bytes,
            .benchmark_core = CONFIG_CRYPTOSE_BENCHMARK_CORE,
        };
    }

    (void) ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    vTaskDelay(1);
    return job.measurement;
}
