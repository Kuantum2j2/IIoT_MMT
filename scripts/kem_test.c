#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

// Hitung selisih waktu dalam milidetik
static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

int main() {

    // >>> inisialisasi OpenSSL 3 agar load config & default provider:
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
        fprintf(stderr, "Gagal inisialisasi OpenSSL 3\n");
        return EXIT_FAILURE;
    }

    // Pakai system RNG sekali untuk memastikan /dev/urandom siap
    uint8_t seed[32];
    OQS_randombytes(seed, sizeof(seed));

    // Pastikan algoritma Kyber-768 tersedia
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768)) {
        fprintf(stderr, "Kyber-768 tidak tersedia\n");
        return EXIT_FAILURE;
    }

    // Inisiasi struktur KEM
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        fprintf(stderr, "Gagal inisiasi KEM\n");
        return EXIT_FAILURE;
    }

    // Alokasikan buffer sesuai panjang parameter KEM
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_e = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);
    struct timespec t0, t1;

    // 1) Key-pair generation
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair gagal\n");
        return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("KeyGen: %.3f ms\n", diff_ms(t0, t1));

    // 2) Encapsulation
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS) {
        fprintf(stderr, "Encapsulation gagal\n");
        return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Encaps: %.3f ms\n", diff_ms(t0, t1));

    // 3) Decapsulation
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Decapsulation gagal\n");
        return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Decaps: %.3f ms\n", diff_ms(t0, t1));

    // 4) Verifikasi shared secret
    printf("Shared OK: %s\n",
        memcmp(ss_e, ss_d, kem->length_shared_secret) == 0 ? "yes" : "NO");

    // Bersihkan memori
    free(pk); free(sk); free(ct); free(ss_e); free(ss_d);
    OQS_KEM_free(kem);
    return EXIT_SUCCESS;
}
