#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../pots.h"
#include "../randombytes.h"
#include "../params.h"

void print_public_key(const xmss_params *params, unsigned char *pk)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < params->wots_w; j++) {
            printf("PK - chain[%d] Node[%d]:\n", i + 1, j + 1);
            for (int k = 0; k < params->n; k++) {
                printf("%02x", pk[(i * params->wots_w + j) * params->n + k]);
            }
            printf("\n");
        }
    }
}

void print_secret_key(const xmss_params *params, unsigned char *sk)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < params->wots_w; j++) {
            printf("SK - chain[%d] Node[%d]:\n", i + 1, j + 1);
            for (int k = 0; k < params->n; k++) {
                printf("%02x", sk[(i * params->wots_w + j) * params->n + k]);
            }
            printf("\n");
        }
    }
}

void print_signature(const xmss_params *params, unsigned char *sig)
{
    for (int i = 0; i < 2; i++) {
        printf("SIG - chain[%d]:\n", i + 1);
        for (int k = 0; k < params->n; k++) {
            printf("%02x", sig[i * params->n + k]);
        }
        printf("\n");
    }
}

int main()
{
    xmss_params params;
    // TODO test more different OIDs
    uint32_t oid = 0x00000001;

    /* For WOTS it doesn't matter if we use XMSS or XMSSMT. */
    xmss_parse_oid(&params, oid);

    unsigned char seed[params.n];
    unsigned char pub_seed[params.n];
    unsigned char sk[params.wots_len1 * params.wots_w * params.n];
    unsigned char pk[params.wots_len1 * params.wots_w * params.n];
    unsigned char sig[params.wots_len1 * params.n];
    unsigned char m[params.n];
    uint32_t addr[8] = {0};

    randombytes(seed, params.n);
    randombytes(pub_seed, params.n);
    randombytes(m, params.n);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing POTS signature and PK derivation.. \n");

    pots_pkgen(&params, sk, pk, seed, pub_seed, addr);

    // print_public_key(&params, pk);
    // print_secret_key(&params, sk);

    pots_sign(&params, sig, m, sk, pub_seed, addr);

    // print_signature(&params, sig);
    
    printf("Verification Result: %d\n", pots_ver(&params, sig, m, pk));
}
