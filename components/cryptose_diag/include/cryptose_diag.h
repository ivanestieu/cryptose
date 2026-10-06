#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* idf_version;
    uint32_t    flash_size_bytes;
    size_t      free_heap_bytes;
    size_t      minimum_free_heap_bytes;
    size_t      stack_high_water_bytes;
    unsigned    cpu_cores;
    unsigned    chip_revision_major;
    unsigned    chip_revision_minor;
    bool        has_wifi;
    bool        has_bluetooth_le;
} cryptose_diag_snapshot_t;

esp_err_t cryptose_diag_capture(cryptose_diag_snapshot_t* snapshot);
void      cryptose_diag_log(const cryptose_diag_snapshot_t* snapshot, unsigned sample);

#ifdef __cplusplus
}
#endif
