#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../pqc_kem/pqc_kem.h"

int main() {
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len = 0, sk_len = 0;

    // 1) Generate keypair
    printf("[*] Generating PQC KEM keypair...\n");
    if (pqc_kem_generate(&pk, &pk_len, &sk, &sk_len) != OQS_SUCCESS) {
        fprintf(stderr, "Error: PQC KEM keypair generation failed\n");
        return EXIT_FAILURE;
    }
    printf("    Public key (%zu bytes), secret key (%zu bytes) generated.\n", pk_len, sk_len);

    // 2) Save public key
    FILE *fpk = fopen("pqc_public.key", "wb");
    if (!fpk || fwrite(pk, 1, pk_len, fpk) != pk_len) {
        fprintf(stderr, "Error: cannot write public key\n");
        free(pk); free(sk);
        return EXIT_FAILURE;
    }
    fclose(fpk);
    printf("    Written public key to pqc_public.key\n");

    // 3) Encapsulation
    size_t ct_len = 0, ss_len = 0;
    uint8_t *ct = malloc(pk_len * 2);
    uint8_t *ss = malloc(sk_len);
    if (!ct || !ss) {
        fprintf(stderr, "Allocation error\n");
        free(pk); free(sk);
        return EXIT_FAILURE;
    }
    printf("[*] Encapsulating...\n");
    if (pqc_kem_encaps(ct, &ct_len, ss, &ss_len, pk, pk_len) != OQS_SUCCESS) {
        fprintf(stderr, "Error: encapsulation failed\n");
        free(pk); free(sk);
        free(ct); free(ss);
        return EXIT_FAILURE;
    }
    printf("    Ciphertext: %zu bytes, Shared secret: %zu bytes\n", ct_len, ss_len);

    // 4) Decapsulation
    uint8_t *ss2 = malloc(ss_len);
    printf("[*] Decapsulating...\n");
    if (pqc_kem_decaps(ss2, &ss_len, ct, ct_len, sk, sk_len) != OQS_SUCCESS) {
        fprintf(stderr, "Error: decapsulation failed\n");
        free(pk); free(sk);
        free(ct); free(ss); free(ss2);
        return EXIT_FAILURE;
    }

    // 5) Verify shared secret
    if (memcmp(ss, ss2, ss_len) == 0) {
        printf("    Shared secret match!\n");
    } else {
        fprintf(stderr, "    Shared secret mismatch!\n");
    }

    // 6) Cleanup
    free(pk); free(sk);
    free(ct); free(ss); free(ss2);
    return EXIT_SUCCESS;
}