#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

int main() {
    printf("RNG backend : %s\n", OQS_randombytes_name());

    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768)) {
        fprintf(stderr, "Kyber-768 is not available\n");
        return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    size_t pk_len = kem->length_public_key,
           sk_len = kem->length_secret_key,
           ct_len = kem->length_ciphertext,
           ss_len = kem->length_shared_secret;

    uint8_t *pk = malloc(pk_len),
            *sk = malloc(sk_len),
            *ct = malloc(ct_len),
            *ss_e = malloc(ss_len),
            *ss_d = malloc(ss_len);

    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_keypair(kem, pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("KeyGen:   %.3f ms\n", diff_ms(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_encaps(kem, ct, ss_e, pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Encaps:   %.3f ms\n", diff_ms(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_decaps(kem, ss_d, ct, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Decaps:   %.3f ms\n", diff_ms(t0, t1));

    printf("Shared OK: %s\n",
        memcmp(ss_e, ss_d, ss_len) == 0 ? "yes" : "NO");

    free(pk); free(sk); free(ct); free(ss_e); free(ss_d);
    OQS_KEM_free(kem);
    return 0;
}
