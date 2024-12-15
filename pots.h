#ifndef XMSS_POTS_H
#define XMSS_POTS_H

#include <stdint.h>
#include "params.h"

/**
 * POTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full POTS private key and computes the corresponding public key.
 *
 * Writes the computed public key to 'pk'.
 */
void pots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed);

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void pots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed);

/**
 * Takes a POTS signature, an n-byte message, and a POTS public key.
 *
 * Verifies the correctness of the signature.
 */
void pots_verification(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg);


#endif
