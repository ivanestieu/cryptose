#include "statistics.h"

#if __has_include(<esp_log.h>)
    #include <esp_log.h>
#else
    #define ESP_LOGI(tag, format, ...) printf(format, ##__VA_ARGS__)
#endif

#include <stddef.h>



bool benchmark_statistics_compute(uint32_t* samples, const size_t count, benchmark_cycle_statistics_t* statistics) {
    if (!samples || !count) {
        ESP_LOGI(__FILE__, "No samples provided");
        return false;
    }

    if (!statistics) {
        ESP_LOGI(__FILE__, "No statistics provided");
        return false;
    }

    (void) samples;
    (void) count;
    (void) statistics;
    /* TODO_STUDENT: trier les échantillons et calculer min/médiane/p95/max. */
    return false;
}
