#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../pots.h"
#include "../randombytes.h"
#include "../params.h"

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

    printf("Testing POTS signature and PK derivation.. ");

    pots_pkgen(&params, sk, pk, seed, pub_seed, addr);

    for (int i = 0; i < 2; i++) {
        printf("PK Chain [%d]: \n", i);
        for (int j = 0; j < params.wots_w; j++) {
            printf("PK Node [%d]:\n", j);
            for (int k = 0; k < params.n; k++) {
                printf("%02x", pk[(i * params.wots_w + j) * params.n + k]);
            }
            printf("/n");
        }
    }

    for (int i = 0; i < 2; i++) {
        printf("SK Chain [%d]: \n", i);
        for (int j = 0; j < params.wots_w; j++) {
            printf("SK Node [%d]:\n", j);
            for (int k = 0; k < params.n; k++) {
                printf("%02x", sk[(i * params.wots_w + j) * params.n + k]);
            }
            printf("/n");
        }
    }

    printf("Message to sign:\n");
    for (int i = 0; i < params.n; i++) {
        printf("%02x", m[i]);
    }
    printf("\n\n");

    pots_sign(&params, sig, m, sk, pub_seed, addr);

    printf("WOTS Signature:\n");
    for (int i = 0; i < params.wots_len1; i++) {
        printf("Chain[%d]: ", i);
        for (int j = 0; j < params.n; j++) {
            printf("%02x", sig[i * params.n + j]);
        }
        printf("\n");
    }

    printf("Verification Result: %d\n", pots_ver(&params, sig, m, pk));

    // wots_pk_from_sig(&params, pk2, sig, m, pub_seed, addr);

    // if (memcmp(pk1, pk2, params.wots_sig_bytes)) {
    //     printf("failed!\n");
    //     return -1;
    // }
    // printf("successful.\n");
    // return 0;
}
