#include "anon-proxy.h"

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    anon_proxy_hash_ctx_update(&ctx, input, input_size);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_h2(anon_proxy_params_t params, mpz_t input, uint8_t *output)
{
    size_t output_size = mpz_sizeinbase(input, 256);
    uint8_t input_bytes[output_size];

    mpz_export(input_bytes, NULL, 1, 1, 0, 0, input);

    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    anon_proxy_hash_ctx_update(&ctx, input_bytes, output_size);
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, output);
}

void anon_proxy_h3(anon_proxy_params_t params, mpz_t input, mpz_t output)
{
    mpz_mod(output, input, params->p);
    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

// TODO: Same as anon_proxy_h1, maybe unsecure?
void anon_proxy_h4(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    anon_proxy_hash_ctx_update(&ctx, input, input_size);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng)
{
}

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk)
{
    mpz_randomm(sk->sk, prng, params->q);
    mpz_mul(pk->pk1, params->g, sk->sk);

    size_t sk_size = mpz_sizeinbase(sk->sk, 256);

    uint8_t sk_0[sk_size + 1];
    uint8_t sk_1[sk_size + 1];
    mpz_export(sk_0, NULL, 1, 1, 0, 0, sk->sk);
    mpz_export(sk_1, NULL, 1, 1, 0, 0, sk->sk);
    sk_0[sk_size] = 0;
    sk_1[sk_size] = 1;

    mpz_t tmp0;
    mpz_t tmp1;
    mpz_inits(tmp0, tmp1, NULL);

    anon_proxy_h4(params, sk_0, sk_size + 1, tmp0);
    anon_proxy_h4(params, sk_1, sk_size + 1, tmp1);

    mpz_mul(tmp1, sk->sk, tmp1);
    mpz_add(tmp0, tmp0, tmp1);
    mpz_powm(pk->pk2, params->g, tmp0, params->p);

    mpz_clears(tmp0, tmp1, NULL);
}

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, elgamal_mod_params_t elgamal_mod_params, anon_proxy_rekey_t rekey)
{
    mpz_t a1, a2, b1, b2, h4_0, h4_1, tmp;
    mpz_inits(a1, a2, b1, b2, tmp, NULL);

    size_t sk_size = mpz_sizeinbase(sk->sk, 256);
    uint8_t sk_0[sk_size + 1];
    uint8_t sk_1[sk_size + 1];
    mpz_export(sk_0, NULL, 1, 1, 0, 0, sk->sk);
    mpz_export(sk_1, NULL, 1, 1, 0, 0, sk->sk);
    sk_0[sk_size] = 0;
    sk_1[sk_size] = 1;

    anon_proxy_h4(params, sk_0, sk_size + 1, h4_0);
    anon_proxy_h4(params, sk_1, sk_size + 1, h4_1);
    mpz_mod(h4_0, h4_0, params->q);
    mpz_mod(h4_1, h4_1, params->q);

    do
    {
        mpz_randomm(a1, prng, params->q);
        mpz_randomm(a2, prng, params->q);
        mpz_mul(tmp, a1, a2);
        mpz_mod(tmp, tmp, params->q);
    } while (mpz_cmp_ui(tmp, h4_0) == 0);

    do
    {
        mpz_randomm(b1, prng, params->q);
        mpz_randomm(b2, prng, params->q);
        mpz_mul(tmp, b1, b2);
        mpz_mod(tmp, tmp, params->q);
    } while (mpz_cmp_ui(tmp, h4_1) == 0);

    mpz_clears(h4_0, h4_1, NULL);

    mpz_t r;
    mpz_init(r);
    mpz_randomm(r, prng, params->q);
    size_t r_size = mpz_sizeinbase(r, 256);
    size_t a2_size = mpz_sizeinbase(a2, 256);
    size_t b2_size = mpz_sizeinbase(b2, 256);

    uint8_t r_a2_b2[r_size + a2_size + b2_size];
    mpz_export(r_a2_b2, NULL, 1, 1, 0, 0, r);
    mpz_export(r_a2_b2 + r_size, NULL, 1, 1, 0, 0, a2);
    mpz_export(r_a2_b2 + r_size + a2_size, NULL, 1, 1, 0, 0, b2);

    mpz_t h1_output;
    mpz_init(h1_output);

    anon_proxy_h1(params, r_a2_b2, r_size + a2_size + b2_size, h1_output);

    mpz_set(rekey->rekey1[0], a1);
    mpz_set(rekey->rekey1[1], b1);

    mpz_powm(rekey->rekey2_1, params->g, h1_output, params->p);

    // mpz_powm(tmp, pk->pk1, h1_output, params->p);

    // uint8_t h2_output[anon_proxy_hash_size];
    // anon_proxy_h2(params, tmp, h2_output);

    mpz_set(elgamal_mod_params->pk, pk->pk1);

    // TODO: Forse a2|b2 == m?
    elgamal_plaintext_t plaintext;
    plaintext->m_size = a2_size + b2_size;
    plaintext->m = r_a2_b2 + r_size;

    elgamal_ciphertext_t ciphertext;

    elgamal_mod_encrypt(params->elgamal_params, prng, plaintext, ciphertext);

    mpz_set(rekey->rekey2_2->c1, ciphertext->c1);
    rekey->rekey2_2->c2 = ciphertext->c2;
    rekey->rekey2_2->c2_size = ciphertext->c2_size;
}

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext)
{
    mpz_t r, r_1;
    mpz_inits(r, r_1, NULL);
    do
    {
        mpz_randomm(r, prng, params->q);
        mpz_randomm(r_1, prng, params->q);
    } while (mpz_cmp(r, r_1) == 0 || mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(r_1, 0) == 0);
    mpz_t A, B, C;
    mpz_inits(A, B, C, NULL);
    mpz_powm(A, params->g, r, params->p);
    mpz_powm(B, pk->pk1, r, params->p);
    mpz_powm(C, params->g, r_1, params->p);

    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, pk->pk2, r, params->p);

    uint8_t h2_output[anon_proxy_hash_size]; //TODO: l??

    anon_proxy_h2(params, h2_input, h2_output);

    elgamal_ciphertext_t elgamal_ciphertext;

    elgamal_mod_encrypt(params->elgamal_params, prng, plaintext, elgamal_ciphertext);

    

}
