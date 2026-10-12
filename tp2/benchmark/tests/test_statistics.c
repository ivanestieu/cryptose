#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "statistics.h"

static void test_distribution_is_computed_with_nearest_rank_percentiles(void) {
    uint32_t                     samples[] = {900, 100, 500, 300, 700};
    benchmark_cycle_statistics_t statistics;

    assert(benchmark_statistics_compute(samples, 5, &statistics));
    assert(statistics.minimum == 100);
    assert(statistics.median == 500);
    assert(statistics.p95 == 900);
    assert(statistics.maximum == 900);
}

static void test_even_sample_count_uses_lower_nearest_rank_median(void) {
    uint32_t                     samples[] = {8, 7, 6, 5, 4, 3, 2, 1};
    benchmark_cycle_statistics_t statistics;

    assert(benchmark_statistics_compute(samples, 8, &statistics));
    assert(statistics.minimum == 1);
    assert(statistics.median == 4);
    assert(statistics.p95 == 8);
    assert(statistics.maximum == 8);
}

static void test_empty_input_is_rejected(void) {
    benchmark_cycle_statistics_t statistics;
    assert(! benchmark_statistics_compute(NULL, 0, &statistics));
}

int main(void) {
    test_distribution_is_computed_with_nearest_rank_percentiles();
    test_even_sample_count_uses_lower_nearest_rank_median();
    test_empty_input_is_rejected();
    puts("statistics contract: OK");
    return 0;
}
