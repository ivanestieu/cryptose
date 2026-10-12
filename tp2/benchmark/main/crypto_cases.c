#include "crypto_cases.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "crypto_vectors.h"
#include "sdkconfig.h"
#include "hal/aes_types.h"

#define AEAD_TAG_BYTES 16
#define SHA256_BYTES   32

/*
 * Each case has two functions:
 *   - verify(): the correctness check, run once before any timing. It must prove the
 *     primitive is right (published vector from crypto_vectors.h, or a round trip) AND
 *     that a tampered input is rejected. It returns PSA_SUCCESS only if both hold.
 *   - execute(): exactly the operation that the "operation" field names, on s_payload.
 *     It is timed 32 times, so it must create and destroy everything it uses (no key
 *     left behind: psa_destroy_key on every path).
 * Return the first PSA error you meet; PSA_ERROR_INVALID_SIGNATURE for a wrong result.
 */

static uint8_t s_payload[CONFIG_CRYPTOSE_BENCHMARK_PAYLOAD_BYTES];
static uint32_t s_nonce_counter = 0;

#define CHECKED_KEY_INIT(attributes, key_id, status, KEY_TYPE, KEY_BITS, KEY_USAGE, KEY_ALGORITHM, KEY_FIXTURE) psa_set_key_type(&attributes, KEY_TYPE); \
    psa_set_key_bits(&attributes, KEY_BITS); \
    psa_set_key_usage_flags(&attributes, KEY_USAGE); \
    psa_set_key_algorithm(&attributes, KEY_ALGORITHM); \
    status = psa_import_key( \
         &attributes, \
         KEY_FIXTURE, \
         sizeof(KEY_FIXTURE), \
         &key_id \
    ); \
    psa_reset_key_attributes(&attributes); \
    if (status != PSA_SUCCESS) { \
        if (key_id != 0) { \
            psa_destroy_key(key_id); \
        } \
        return status; \
    } \

#define CHECKED_ENCRYPT_OR_DECRYPT(MODE, status, key_id, ALGORITHM, NONCE, AAD, PAYLOAD, CIPHER, cipher_len)  status = psa_aead_##MODE( \
        key_id, \
        ALGORITHM, \
        NONCE, \
        sizeof(NONCE), \
        AAD, \
        sizeof(AAD), \
        PAYLOAD, \
        sizeof(PAYLOAD), \
        CIPHER, \
        sizeof(CIPHER), \
        &cipher_len \
    ); \
     \
    if (status != PSA_SUCCESS) { \
        if (key_id != 0) { \
            psa_destroy_key(key_id); \
        } \
        return status; \
    } \

#define CHECKED_ENCRYPT(status, key_id, ALGORITHM, NONCE, AAD, PAYLOAD, CIPHER, cipher_len) \
    CHECKED_ENCRYPT_OR_DECRYPT(encrypt, status, key_id, ALGORITHM, NONCE, AAD, PAYLOAD, CIPHER, cipher_len)
#define CHECKED_DECRYPT(status, key_id, ALGORITHM, NONCE, AAD, CIPHER, PLAIN, cipher_len) \
    CHECKED_ENCRYPT_OR_DECRYPT(decrypt, status, key_id, ALGORITHM, NONCE, AAD, CIPHER, PLAIN, cipher_len)


void crypto_cases_prepare_payload(void) {
    for (size_t index = 0; index < sizeof(s_payload); ++index) {
        s_payload[index] = (uint8_t) (index & 0xffU);
    }
}

/* ---- Worked example: SHA-256 (no key, so no key policy to manage). ---- */

static psa_status_t run_sha_256(void) {
    uint8_t digest[SHA256_BYTES];
    size_t  digest_length = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, s_payload, sizeof(s_payload), digest, sizeof(digest), &digest_length);
}

static psa_status_t verify_sha_256(void) {
    uint8_t      digest[SHA256_BYTES];
    size_t       digest_length = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, KAT_SHA256_MESSAGE, sizeof(KAT_SHA256_MESSAGE), digest,
                                           sizeof(digest), &digest_length);
    if (status == PSA_SUCCESS && (digest_length != sizeof(KAT_SHA256_DIGEST) ||
                                  memcmp(digest, KAT_SHA256_DIGEST, sizeof(KAT_SHA256_DIGEST)) != 0)) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }
    return status;
}

/* ---- AES-256-GCM: import-encrypt-decrypt of s_payload with FIXTURE_AAD. ---- */

static psa_status_t run_aes_256_gcm(void) {
    /* TODO_STUDENT: import FIXTURE_AES_KEY (usage ENCRYPT|DECRYPT, algorithm PSA_ALG_GCM), encrypt then
       decrypt s_payload with a fresh nonce, check the round trip, destroy the key. */
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t key_id = 0;
    struct psa_key_attributes_s attributes = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t nonce[12];
    uint8_t cipher[sizeof(s_payload) + AEAD_TAG_BYTES];
    uint8_t decrypt[sizeof(s_payload)];

    size_t cipher_len = 0;
    size_t decrypt_len = 0;

    CHECKED_KEY_INIT(attributes, key_id, status, PSA_KEY_TYPE_AES, 256, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_GCM, FIXTURE_AES_KEY);

    memcpy(nonce, FIXTURE_NONCE_PREFIX, sizeof(FIXTURE_NONCE_PREFIX));

    s_nonce_counter++;

    nonce[8] = s_nonce_counter >> 24;
    nonce[9] = s_nonce_counter >> 16;
    nonce[10] = s_nonce_counter >> 8;
    nonce[11] = s_nonce_counter;

    CHECKED_ENCRYPT(status, key_id, PSA_ALG_GCM, nonce, FIXTURE_AAD, s_payload, cipher, cipher_len);
    CHECKED_DECRYPT(status, key_id, PSA_ALG_GCM, nonce, FIXTURE_AAD, cipher, decrypt, decrypt_len);

    if (decrypt_len != sizeof(s_payload) || memcmp(decrypt, s_payload, sizeof(s_payload)) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

    if (key_id != 0) {
        status = psa_destroy_key(key_id);
    }

    return status;
}

static psa_status_t verify_aes_256_gcm(void) {
    /* TODO_STUDENT: KAT_AES_GCM_* must give KAT_AES_GCM_CIPHERTEXT || KAT_AES_GCM_TAG, decrypt back to
       the plaintext, and flipping a ciphertext byte (not a tag byte) must be refused with
       PSA_ERROR_INVALID_SIGNATURE. */
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t key_id = 0;
    struct psa_key_attributes_s attributes = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t cipher[sizeof(KAT_AES_GCM_CIPHERTEXT) + sizeof(KAT_AES_GCM_TAG)];
    uint8_t decrypt[sizeof(KAT_AES_GCM_PLAINTEXT)];

    size_t cipher_len = 0;
    size_t decrypt_len = 0;

    CHECKED_KEY_INIT(attributes, key_id, status, PSA_KEY_TYPE_AES, 256, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_GCM, KAT_AES_GCM_KEY)

    CHECKED_ENCRYPT(status, key_id, PSA_ALG_GCM, KAT_AES_GCM_NONCE, KAT_AES_GCM_AAD, KAT_AES_GCM_PLAINTEXT, cipher, cipher_len);

    if (status == PSA_SUCCESS && (cipher_len != sizeof(KAT_AES_GCM_CIPHERTEXT) ||
                                      memcmp(cipher, KAT_AES_GCM_CIPHERTEXT, sizeof(KAT_AES_GCM_CIPHERTEXT)) != 0 ||
                                      memcmp(cipher + sizeof(KAT_AES_GCM_CIPHERTEXT), KAT_AES_GCM_TAG,sizeof(KAT_AES_GCM_TAG)) != 0)) {
        if (key_id != 0) {
            psa_destroy_key(key_id);
        }
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    CHECKED_DECRYPT(status, key_id, PSA_ALG_GCM, KAT_AES_GCM_NONCE, KAT_AES_GCM_AAD, cipher, decrypt, decrypt_len);

    if (decrypt_len != sizeof(s_payload) || memcmp(decrypt, s_payload, sizeof(s_payload)) != 0) {
        psa_destroy_key(key_id);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    cipher[0] ^= 0x1E;

    status = psa_aead_decrypt(
        key_id,
        PSA_ALG_GCM,
        KAT_AES_GCM_NONCE,
        sizeof(KAT_AES_GCM_NONCE),
        KAT_AES_GCM_AAD,
        sizeof(KAT_AES_GCM_AAD),
        cipher,
        sizeof(cipher),
        cipher,
        sizeof(cipher),
        &cipher_len
    );

    status = status == PSA_ERROR_INVALID_SIGNATURE ? PSA_SUCCESS : status == PSA_SUCCESS ? PSA_ERROR_INVALID_SIGNATURE : status;

    if (key_id != 0) {
        const psa_status_t tmp = psa_destroy_key(key_id);
        if (status == PSA_SUCCESS) {
            status = tmp;
        }
    }

    return status;
}

#if CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305
/* ---- ChaCha20-Poly1305: same contract as AES-GCM (reuse your code). ---- */

static psa_status_t run_chacha20_poly1305(void) {
    /* TODO_STUDENT: as run_aes_256_gcm, with FIXTURE_CHACHA_KEY and PSA_ALG_CHACHA20_POLY1305. */
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t verify_chacha20_poly1305(void) {
    /* TODO_STUDENT: as verify_aes_256_gcm, with the KAT_CHACHA_* vector (RFC 8439). */
    return PSA_ERROR_NOT_SUPPORTED;
}
#endif

/* ---- HMAC-SHA-256: import-mac of s_payload. ---- */

static psa_status_t run_hmac_sha_256(void) {
    /* TODO_STUDENT: import KAT_HMAC_KEY as a PSA_KEY_TYPE_HMAC key (usage SIGN_MESSAGE), MAC s_payload,
       destroy the key. */

    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t key_id = 0;
    struct psa_key_attributes_s attributes = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t mac[SHA256_BYTES];

    size_t mac_len = 0;

    CHECKED_KEY_INIT(attributes, key_id, status, PSA_KEY_TYPE_HMAC, 256, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256), KAT_HMAC_KEY);

    status = psa_mac_compute(
        key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        s_payload,
        sizeof(s_payload),
        mac,
        sizeof(mac),
        &mac_len
    );

    if (key_id != 0) {
        status = psa_destroy_key(key_id);
    }

    return status;
}

static psa_status_t verify_hmac_sha_256(void) {
    /* TODO_STUDENT: KAT_HMAC_MESSAGE must give KAT_HMAC_SHA256_MAC (RFC 4231, test case 1). */
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t key_id = 0;
    struct psa_key_attributes_s attributes = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t mac[SHA256_BYTES];

    size_t mac_len = 0;

    CHECKED_KEY_INIT(attributes, key_id, status, PSA_KEY_TYPE_HMAC, 256, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256), KAT_HMAC_KEY);

    status = psa_mac_compute(
        key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        KAT_HMAC_MESSAGE,
        sizeof(KAT_HMAC_MESSAGE),
        mac,
        sizeof(mac),
        &mac_len
    );

    if (status == PSA_SUCCESS && (mac_len != sizeof(KAT_HMAC_SHA256_MAC) ||
                                      memcmp(mac, KAT_HMAC_SHA256_MAC, sizeof(KAT_HMAC_SHA256_MAC)) != 0)) {
        if (key_id != 0) {
            psa_destroy_key(key_id);
        }
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (key_id != 0) {
        status = psa_destroy_key(key_id);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/* ---- ECDH P-256 and X25519: two key generations + two raw agreements that must agree. ---- */

static psa_status_t run_ecdh_p256(void) {
    /* TODO_STUDENT: generate two key pairs (PSA_ECC_FAMILY_SECP_R1, 256 bits, usage DERIVE, PSA_ALG_ECDH),
       export both public keys, compute both raw agreements, check they are equal, destroy both keys. */
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t run_x25519(void) {
    /* TODO_STUDENT: the same with PSA_ECC_FAMILY_MONTGOMERY, 255 bits. */
    return PSA_ERROR_NOT_SUPPORTED;
}

/* ---- ECDSA P-256 over SHA-256: hash s_payload, generate a key, sign, verify. ---- */

static psa_status_t run_ecdsa_p256(void) {
    /* TODO_STUDENT: hash s_payload, generate a SECP_R1 256-bit key pair (usage SIGN_HASH|VERIFY_HASH,
       PSA_ALG_ECDSA(PSA_ALG_SHA_256)), sign the hash, verify the signature, destroy the key. */
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t verify_ecdsa_p256(void) {
    /* TODO_STUDENT: same as run_ecdsa_p256, plus: a signature with one flipped bit must be refused. */
    return PSA_ERROR_NOT_SUPPORTED;
}

/* The case list is the JSONL contract: do not rename, reorder or remove entries. */
static const crypto_case_t CASES[] = {
    {.algorithm     = "aes-256-gcm",
     .operation     = "import-encrypt-decrypt",
     .payload_bytes = sizeof(s_payload),
     .verify        = verify_aes_256_gcm,
     .execute       = run_aes_256_gcm},
    {.algorithm     = "sha-256",
     .operation     = "hash",
     .payload_bytes = sizeof(s_payload),
     .verify        = verify_sha_256,
     .execute       = run_sha_256},
    {.algorithm     = "hmac-sha-256",
     .operation     = "import-mac",
     .payload_bytes = sizeof(s_payload),
     .verify        = verify_hmac_sha_256,
     .execute       = run_hmac_sha_256},
    {.algorithm     = "ecdh-p256",
     .operation     = "two-keygen-two-agreements",
     .payload_bytes = 0,
     .verify        = run_ecdh_p256,
     .execute       = run_ecdh_p256},
    {.algorithm     = "x25519",
     .operation     = "two-keygen-two-agreements",
     .payload_bytes = 0,
     .verify        = run_x25519,
     .execute       = run_x25519},
    {.algorithm     = "ecdsa-p256-sha-256",
     .operation     = "hash-keygen-sign-verify",
     .payload_bytes = sizeof(s_payload),
     .verify        = verify_ecdsa_p256,
     .execute       = run_ecdsa_p256},
#if CONFIG_CRYPTOSE_ENABLE_CHACHA20_POLY1305
    {.algorithm     = "chacha20-poly1305",
     .operation     = "import-encrypt-decrypt",
     .payload_bytes = sizeof(s_payload),
     .verify        = verify_chacha20_poly1305,
     .execute       = run_chacha20_poly1305},
#endif
};

const crypto_case_t* crypto_cases_get(size_t* count) {
    if (count != NULL) {
        *count = sizeof(CASES) / sizeof(CASES[0]);
    }
    return CASES;
}
