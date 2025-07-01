// File: src/pqc_kem/pqc_kem.c
#include "pqc_kem.h"
#include <oqs/kem.h>    // memastikan OQS_KEM_alg_* & OQS_DEFAULT_KEM_NAME tersedia
#include <stdlib.h>
#include <string.h>

int pqc_kem_generate(uint8_t **pk, size_t *pk_len,
                     uint8_t **sk, size_t *sk_len) {
    OQS_KEM *kem = OQS_KEM_new(OQS_DEFAULT_KEM_NAME);
    if (kem == NULL) {
        return OQS_ERROR;
    }
    *pk_len = kem->length_public_key;
    *sk_len = kem->length_secret_key;
    *pk = malloc(*pk_len);
    *sk = malloc(*sk_len);
    if (*pk == NULL || *sk == NULL) {
        free(*pk);
        free(*sk);
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    if (OQS_KEM_keypair(kem, *pk, *sk) != OQS_SUCCESS) {
        free(*pk);
        free(*sk);
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    OQS_KEM_free(kem);
    return OQS_SUCCESS;
}

int pqc_kem_encaps(uint8_t *ct, size_t *ct_len,
                   uint8_t *ss, size_t *ss_len,
                   const uint8_t *pk, size_t pk_len) {
    OQS_KEM *kem = OQS_KEM_new(OQS_DEFAULT_KEM_NAME);
    if (kem == NULL) {
        return OQS_ERROR;
    }
    if (pk_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    *ct_len = kem->length_ciphertext;
    *ss_len = kem->length_shared_secret;
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    OQS_KEM_free(kem);
    return OQS_SUCCESS;
}

int pqc_kem_decaps(uint8_t *ss, size_t *ss_len,
                   const uint8_t *ct, size_t ct_len,
                   const uint8_t *sk, size_t sk_len) {
    OQS_KEM *kem = OQS_KEM_new(OQS_DEFAULT_KEM_NAME);
    if (kem == NULL) {
        return OQS_ERROR;
    }
    if (ct_len != kem->length_ciphertext ||
        sk_len != kem->length_secret_key) {
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    *ss_len = kem->length_shared_secret;
    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return OQS_ERROR;
    }
    OQS_KEM_free(kem);
    return OQS_SUCCESS;
}
