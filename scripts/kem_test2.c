#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

// Waktu dalam milidetik
static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

int main() {
    // Paksa satu kali pembacaan RNG dari sistem
    uint8_t dummy[32];
    OQS_randombytes(dummy, sizeof(dummy));

    //if (OQS_randombytes(dummy, sizeof(dummy)) != OQS_SUCCESS) {
    //    fprintf(stderr, "Gagal baca system RNG\n");
    //    return 1;
    //}

    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768)) {
        fprintf(stderr, "Kyber-768 tidak tersedia\n");
        return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        fprintf(stderr, "Gagal inisiasi KEM\n");
        return 1;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_e = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);
    struct timespec t0, t1;

    // KeyGen
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_keypair(kem, pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("KeyGen: %.3f ms\n", diff_ms(t0, t1));

    // Encaps
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_encaps(kem, ct, ss_e, pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Encaps: %.3f ms\n", diff_ms(t0, t1));

    // Decaps
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_decaps(kem, ss_d, ct, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Decaps: %.3f ms\n", diff_ms(t0, t1));

    // Verifikasi
    printf("Shared OK: %s\n",
        memcmp(ss_e, ss_d, kem->length_shared_secret) == 0 ? "yes" : "NO");

    // Cleanup
    free(pk); free(sk); free(ct); free(ss_e); free(ss_d);
    OQS_KEM_free(kem);
    return 0;
}
