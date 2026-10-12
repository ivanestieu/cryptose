#pragma once

#include <stddef.h>

#include "psa/crypto.h"

typedef psa_status_t (*crypto_case_function_t)(void);

typedef struct {
    const char*            algorithm;
    const char*            operation;
    size_t                 payload_bytes;
    crypto_case_function_t verify;
    crypto_case_function_t execute;
} crypto_case_t;

void                 crypto_cases_prepare_payload(void);
const crypto_case_t* crypto_cases_get(size_t* count);
