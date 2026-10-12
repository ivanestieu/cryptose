#include "statistics.h"

#if __has_include(<esp_log.h>)
    #include <esp_log.h>
#else
    #include <stdio.h>
    #define ESP_LOGE(tag, format, ...) printf(format, ##__VA_ARGS__); printf("\n")
    #define ESP_LOGI(tag, format, ...) printf(format, ##__VA_ARGS__); printf("\n")
    #define ESP_LOGD(tag, format, ...) printf(format, ##__VA_ARGS__); printf("\n")
#endif

#include <stddef.h>


static void heapify(uint32_t *arr, const size_t n, const size_t i)
{
    size_t largest = i;
    const size_t l = 2 * i + 1;
    const size_t r = 2 * i + 2;

    if (l < n && arr[l] > arr[largest])
    {
        largest = l;
    }

    if (r < n && arr[r] > arr[largest])
    {
        largest = r;
    }

    if (largest != i)
    {
        const uint32_t temp = arr[i];
        arr[i] = arr[largest];
        arr[largest] = temp;

        heapify(arr, n, largest);
    }
}


/// Geeks for Geeks algorithm O(nlog(n)) execution worst case, O(1) space
static void heap_sort(uint32_t *arr, const size_t n){

    for (uint32_t i = n / 2; i > 0; i--)
    {
        heapify(arr, n, i - 1);
    }

    for (size_t i = n - 1; i > 0; i--)
    {
        const uint32_t temp = arr[0];
        arr[0] = arr[i];
        arr[i] = temp;

        heapify(arr, i, 0);
    }
}


bool benchmark_statistics_compute(uint32_t* samples, const size_t count, benchmark_cycle_statistics_t* statistics) {
    if (!samples || !count) {
        ESP_LOGE(__FILE__, "No samples provided");
        return false;
    }

    if (!statistics) {
        ESP_LOGE(__FILE__, "No statistics provided");
        return false;
    }

    heap_sort(samples, count);
    ESP_LOGD(__FILE__, "Sorted samples");

    const size_t p95_index = (size_t)(0.95 * count);
    statistics->minimum = samples[0];
    statistics->median = samples[count / 2 - (count % 2 == 0)];
    statistics->p95 = samples[p95_index - (p95_index >= count)];
    statistics->maximum = samples[count - 1];
    ESP_LOGI(__FILE__, "Min: %u, Median: %u, P95: %u, Max: %u", statistics->minimum, statistics->median, statistics->p95, statistics->maximum);

    return true;
}
