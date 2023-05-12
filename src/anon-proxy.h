#ifndef ANON_PROXY_H
#define ANON_PROXY_H

#include <gmp.h>
#include <nettle/sha3.h>
#include <stdbool.h>

typedef enum {
    elgamal_public_key_type,
    elgamal_secret_key_type
} elgamal_key_type_t;

struct anon_proxy_shared_params_struct
{
    unsigned int q_bits;

    mpz_t g;
    mpz_t q;
};
typedef struct anon_proxy_shared_params_struct anon_proxy_shared_params_t[1];



void anon_proxy_shared_params_init(anon_proxy_shared_params_t params,
                                   unsigned int q_bits);

#endif // ANON_PROXY_H