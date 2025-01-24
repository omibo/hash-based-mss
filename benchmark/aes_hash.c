#include <time.h>
#include <openssl/evp.h>
#include <string.h>

#include "../utils.h"
#include "../hash.h"
#include "../wots.h"
#include "../hash_address.h"
#include "../params.h"
#include "../randombytes.h"

void benchmark_comparison(const xmss_params *params) {
    const int NUM_ROUNDS = 50;    // Number of full test iterations
    const int NUM_TESTS = 10000;  // Tests per round
    
    printf("\n=== AES vs thash_f Benchmark ===\n");
    printf("Running %d rounds of %d operations each\n\n", NUM_ROUNDS, NUM_TESTS);
    
    double total_thash = 0.0;
    double total_aes = 0.0;
    
    for(int round = 0; round < NUM_ROUNDS; round++) {
        unsigned char in[params->n];
        unsigned char out[params->n];
        unsigned char pub_seed[params->n];
        unsigned char key[32];
        uint32_t addr[8] = {0};
        
        randombytes(in, params->n);
        randombytes(pub_seed, params->n);
        randombytes(key, 32);

        // Time thash_f
        clock_t start = clock();
        for(int i = 0; i < NUM_TESTS; i++) {
            thash_f(params, out, in, pub_seed, addr);
        }
        clock_t end = clock();
        double time_thash = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        
        // Time AES
        start = clock();
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outlen;
        for(int i = 0; i < NUM_TESTS; i++) {
            unsigned char iv[16] = {0};
            unsigned char ctr[16] = {0};
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
            EVP_EncryptUpdate(ctx, out, &outlen, in, params->n);
        }
        EVP_CIPHER_CTX_free(ctx);
        end = clock();
        double time_aes = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        
        total_thash += time_thash;
        total_aes += time_aes;
        
        printf("Round %d:\n", round + 1);
        printf("  thash_f: %.3f ms\n", time_thash);
        printf("  AES:     %.3f ms\n", time_aes);
        printf("  Ratio:   %.2fx\n\n", time_thash/time_aes);
    }
    
    printf("Averages:\n");
    printf("  thash_f: %.3f ms\n", total_thash/NUM_ROUNDS);
    printf("  AES:     %.3f ms\n", total_aes/NUM_ROUNDS);
    printf("  Ratio:   %.2fx\n", (total_thash/NUM_ROUNDS)/(total_aes/NUM_ROUNDS));
}

int main() {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    benchmark_comparison(&params);
    
    return 0;
}