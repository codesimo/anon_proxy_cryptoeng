#ifndef ANON_PROXY_H
#define ANON_PROXY_H
#include "elgamal-mod.h"

struct anon_proxy_params_struct
{

    size_t p_bits;
    size_t q_bits;
    size_t lambda;

    /* elementi pubblici: */
    mpz_t p;
    mpz_t q;
    mpz_t g;

    mpz_t pk;
    mpz_t sk;
};

typedef struct anon_proxy_params_struct *anon_proxy_params_ptr;
typedef struct anon_proxy_params_struct anon_proxy_params_t[1];

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output);
void anon_proxy_h2(mpz_t input, uint8_t *output);

void anon_proxy_h3(mpz_t input, mpz_t output);

void anon_proxy_h4(uint8_t *input, size_t input_size, mpz_t output);

void anon_proxy_init(anon_proxy_params_t params, elgamal_mod_lambda lambda,
                     gmp_randstate_t prng);

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng);

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng);
#endif // ANON_PROXY_H