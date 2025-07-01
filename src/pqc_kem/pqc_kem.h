// File: src/pqc_kem/pqc_kem.h
#ifndef PQC_KEM_H
#define PQC_KEM_H

#include <stdint.h>
#include <stddef.h>
#include <oqs/kem.h>     // <<< wajib: mendefinisikan OQS_KEM_alg_*

#ifdef __cplusplus
extern "C" {
#endif

// Jika belum didefinisikan, gunakan Kyber512 sebagai default KEM
#ifndef OQS_DEFAULT_KEM_NAME
#define OQS_DEFAULT_KEM_NAME OQS_KEM_alg_kyber_512
#endif

/**
 * Generate a PQC KEM keypair using the default algorithm.
 *
 * @param[out] pk      Pointer ke buffer public key (dialokasikan di dalam)
 * @param[out] pk_len  Panjang buffer public key
 * @param[out] sk      Pointer ke buffer secret key (dialokasikan di dalam)
 * @param[out] sk_len  Panjang buffer secret key
 * @return             OQS_SUCCESS atau OQS_ERROR
 */
int pqc_kem_generate(uint8_t **pk, size_t *pk_len,
                     uint8_t **sk, size_t *sk_len);

/**
 * Encapsulate: menghasilkan ciphertext dan shared secret.
 *
 * @param[out] ct      Buffer untuk ciphertext (alokasi di dalam)
 * @param[out] ct_len  Panjang ciphertext
 * @param[out] ss      Buffer untuk shared secret (alokasi di dalam)
 * @param[out] ss_len  Panjang shared secret
 * @param[in]  pk      Public key hasil pqc_kem_generate()
 * @param[in]  pk_len  Panjang public key
 * @return             OQS_SUCCESS atau OQS_ERROR
 */
int pqc_kem_encaps(uint8_t *ct, size_t *ct_len,
                   uint8_t *ss, size_t *ss_len,
                   const uint8_t *pk, size_t pk_len);

/**
 * Decapsulate: memulihkan shared secret dari ciphertext.
 *
 * @param[out] ss      Buffer untuk shared secret (alokasi di dalam)
 * @param[out] ss_len  Panjang shared secret
 * @param[in]  ct      Ciphertext hasil pqc_kem_encaps()
 * @param[in]  ct_len  Panjang ciphertext
 * @param[in]  sk      Secret key hasil pqc_kem_generate()
 * @param[in]  sk_len  Panjang secret key
 * @return             OQS_SUCCESS atau OQS_ERROR
 */
int pqc_kem_decaps(uint8_t *ss, size_t *ss_len,
                   const uint8_t *ct, size_t ct_len,
                   const uint8_t *sk, size_t sk_len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // PQC_KEM_H
