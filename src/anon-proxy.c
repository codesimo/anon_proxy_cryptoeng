#include <string.h>

#include "anon-proxy.h"

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    uint8_t padding[1];
    padding[0] = 0x00;
    anon_proxy_hash_ctx_update(&ctx, 1, padding);
    anon_proxy_hash_ctx_update(&ctx, input_size, input);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_h2(anon_proxy_params_t params, mpz_t input, uint8_t *output)
{
    size_t input_size = mpz_sizeinbase(input, 256);
    uint8_t input_bytes[input_size];

    mpz_export(input_bytes, NULL, 1, 1, 0, 0, input);

    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    anon_proxy_hash_ctx_update(&ctx, input_size, input_bytes);
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_ske_key_size, output);
}

void anon_proxy_h3(anon_proxy_params_t params, mpz_t input, mpz_t output)
{
    mpz_mod(output, input, params->p);
    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_h4(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    uint8_t padding[1];
    padding[0] = 0x01;
    anon_proxy_hash_ctx_update(&ctx, 1, padding);
    anon_proxy_hash_ctx_update(&ctx, input_size, input);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng, anon_proxy_lambda lambda)
{
    assert(params);
    assert(prng);
    assert((lambda == 80) || (lambda == 112) || (lambda == 128));

    mpz_t k, a, tmp;
    mpz_inits(k, a, tmp, NULL);
    mpz_inits(params->p, params->q, params->g, NULL);
    params->lambda = lambda;
    switch (lambda)
    {
    case 80:
        params->p_bits = 1024;
        break;
    case 112:
        params->p_bits = 2048;
        break;
    case 128:
        params->p_bits = 3072;
        break;
    }
    params->q_bits = lambda * 2;

    /* q primo lungo q_bits */
    do
    {
        mpz_urandomb(params->q, prng, params->q_bits);
    } while ((mpz_sizeinbase(params->q, 2) < params->q_bits) ||
             !mpz_probab_prime_p(params->q, anon_proxy_mr_iterations));

    /* p=k*q+1 primo lungo p_bits */
    do
    {
        unsigned int k_bits = params->p_bits - params->q_bits;

        /* k lungo k_bits */
        do
            mpz_urandomb(k, prng, k_bits);
        while (mpz_sizeinbase(k, 2) < k_bits);

        /* p = k*q + 1 */
        mpz_mul(params->p, params->q, k);
        mpz_add_ui(params->p, params->p, 1);
    } while ((mpz_sizeinbase(params->p, 2) < params->p_bits) ||
             !mpz_probab_prime_p(params->p, anon_proxy_mr_iterations));

    /* g generatore del sottogruppo di ordine q: g!=1 && g^q=1 */
    do
    {
        mpz_urandomm(a, prng, params->p);

        /* g = a^k mod p */
        mpz_powm(params->g, a, k, params->p);

        /* tmp = g^q mod p */
        mpz_powm(tmp, params->g, params->q, params->p);
    } while ((mpz_cmp_ui(params->g, 1) == 0) || (mpz_cmp_ui(tmp, 1) != 0));

    pmesg(msg_verbose, "Initialization completed");
    pmesg_mpz(msg_very_verbose, "modulo", params->p);
    pmesg_mpz(msg_very_verbose, "ordine del sottogruppo", params->q);
    pmesg_mpz(msg_very_verbose, "generatore del sottogruppo", params->g);
}

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk)
{
    mpz_urandomm(sk->sk, prng, params->q);
    mpz_mul(pk->pk1, params->g, sk->sk);
    mpz_mod(pk->pk1, pk->pk1, params->p);

    size_t sk_size = mpz_sizeinbase(sk->sk, 256);

    uint8_t sk_0[sk_size + 1];
    uint8_t sk_1[sk_size + 1];
    mpz_export(sk_0, NULL, 1, 1, 0, 0, sk->sk);
    mpz_export(sk_1, NULL, 1, 1, 0, 0, sk->sk);
    sk_0[sk_size] = 0;
    sk_1[sk_size] = 1;

    mpz_t tmp0, tmp1;
    mpz_inits(tmp0, tmp1, NULL);

    anon_proxy_h4(params, sk_0, sk_size + 1, tmp0);
    anon_proxy_h4(params, sk_1, sk_size + 1, tmp1);

    mpz_mul(tmp1, sk->sk, tmp1);
    mpz_add(tmp0, tmp0, tmp1);
    mpz_powm(pk->pk2, params->g, tmp0, params->p);

    pmesg_mpz(msg_very_verbose, "sk", sk->sk);
    pmesg_mpz(msg_very_verbose, "pk1", pk->pk1);
    pmesg_mpz(msg_very_verbose, "pk2", pk->pk2);

    mpz_clears(tmp0, tmp1, NULL);
}

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, anon_proxy_rekey_t rekey)
{
    mpz_t a1, a2, b1, b2, h4_0, h4_1, tmp;
    mpz_inits(a1, a2, b1, b2, tmp, NULL);

    // H4(x||0) e H4(x||1)
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

    // a1 * a2 = H4(x||0) mod q
    do
    {
        mpz_urandomm(a1, prng, params->q);
        mpz_urandomm(a2, prng, params->q);
        mpz_mul(tmp, a1, a2);
        mpz_mod(tmp, tmp, params->q);
    } while (mpz_cmp(tmp, h4_0) == 0);

    // b1 * b2 = H4(x||1) mod q
    do
    {
        mpz_urandomm(b1, prng, params->q);
        mpz_urandomm(b2, prng, params->q);
        mpz_mul(tmp, b1, b2);
        mpz_mod(tmp, tmp, params->q);
    } while (mpz_cmp(tmp, h4_1) == 0);

    mpz_clears(h4_0, h4_1, NULL);

    // random r
    mpz_t r;
    mpz_init(r);
    mpz_urandomm(r, prng, params->q);
    size_t r_size = mpz_sizeinbase(r, 256);
    size_t a2_size = mpz_sizeinbase(a2, 256);
    size_t b2_size = mpz_sizeinbase(b2, 256);

    // r||a2||b2
    size_t pad = anon_proxy_ske_block_size - ((r_size + a2_size + b2_size) % anon_proxy_ske_block_size);
    uint8_t r_a2_b2[r_size + a2_size + b2_size + pad];
    memset(r_a2_b2, 0, r_size + a2_size + b2_size + pad);

    mpz_export(r_a2_b2, NULL, 1, 1, 0, 0, r);
    mpz_export(r_a2_b2 + r_size, NULL, 1, 1, 0, 0, a2);
    mpz_export(r_a2_b2 + r_size + a2_size, NULL, 1, 1, 0, 0, b2);

    // H1(r||a2||b2)
    mpz_t h1_output;
    mpz_init(h1_output);

    anon_proxy_h1(params, r_a2_b2, r_size + a2_size + b2_size, h1_output);

    // rk1 = (a1, b1)
    mpz_set(rekey->rekey1[0], a1);
    mpz_set(rekey->rekey1[1], b1);

    // rk2 = (g^h1, ...)
    mpz_powm(rekey->rekey2_1, params->g, h1_output, params->p);

    // pk1^H1_output
    mpz_powm(tmp, pk->pk1, h1_output, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    anon_proxy_h2(params, tmp, h2_output);

    struct anon_proxy_ske_ctx ctx;
    anon_proxy_ske_set_encypt_key(&(ctx), h2_output);

    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);

    anon_proxy_ske_block_encrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_encrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 r_size + a2_size + b2_size + pad,
                                 rekey->rekey2_2,
                                 r_a2_b2);

    rekey->rekey2_2_size = r_size + a2_size + b2_size + pad;

    mpz_clears(a1, a2, b1, b2, tmp, r, h1_output, NULL);

    // mpz_set(elgamal_mod_params->pk, pk->pk1);

    // // TODO: Forse a2|b2 == m?
    // elgamal_plaintext_t plaintext;
    // plaintext->m_size = a2_size + b2_size;
    // plaintext->m = r_a2_b2 + r_size;

    // elgamal_ciphertext_t ciphertext;

    // elgamal_mod_encrypt(params->elgamal_params, prng, plaintext, ciphertext);

    // mpz_set(rekey->rekey2_2->c1, ciphertext->c1);
    // rekey->rekey2_2->c2 = ciphertext->c2;
    // rekey->rekey2_2->c2_size = ciphertext->c2_size;
}

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext)
{
    // random r, r_1 that are different from 0 and from each other
    mpz_t r, r_1;
    mpz_inits(r, r_1, NULL);
    do
    {
        mpz_urandomm(r, prng, params->q);
        mpz_urandomm(r_1, prng, params->q);
    } while (mpz_cmp(r, r_1) == 0 || mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(r_1, 0) == 0);

    mpz_inits(ciphertext->A, ciphertext->B, ciphertext->C, NULL);
    mpz_powm(ciphertext->A, params->g, r, params->p);
    mpz_powm(ciphertext->B, pk->pk1, r, params->p);
    mpz_powm(ciphertext->C, params->g, r_1, params->p);

    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, pk->pk2, r, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];

    anon_proxy_h2(params, h2_input, h2_output);

    struct anon_proxy_ske_ctx ctx;
    anon_proxy_ske_set_encypt_key(&(ctx), h2_output);

    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);

    size_t to_add = anon_proxy_ske_block_size - (plaintext->m_size % anon_proxy_ske_block_size);
    uint8_t *msg_pad;

    if (to_add == 0)
    {
        msg_pad = plaintext->m;
    }
    else
    {
        msg_pad = malloc(plaintext->m_size + to_add);
        memcpy(msg_pad, plaintext->m, plaintext->m_size);
        memset(msg_pad + plaintext->m_size, 0, to_add);
    }
    ciphertext->D_size = plaintext->m_size + to_add;
    ciphertext->D = malloc(ciphertext->D_size);

    anon_proxy_ske_block_encrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_encrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 plaintext->m_size + to_add,
                                 ciphertext->D,
                                 msg_pad);

    size_t A_size = mpz_sizeinbase(ciphertext->A, 256);
    size_t B_size = mpz_sizeinbase(ciphertext->B, 256);
    size_t C_size = mpz_sizeinbase(ciphertext->C, 256);

    uint8_t h3_input[A_size + B_size + C_size + ciphertext->D_size];
    mpz_export(h3_input, NULL, 1, 1, 0, 0, ciphertext->A);
    mpz_export(h3_input + A_size, NULL, 1, 1, 0, 0, ciphertext->B);
    mpz_export(h3_input + A_size + B_size, NULL, 1, 1, 0, 0, ciphertext->C);
    memcpy(h3_input + A_size + B_size + C_size, ciphertext->D, ciphertext->D_size);

    mpz_t h3_output;
    mpz_init(h3_output);
    mpz_t h3_input_mpz;
    mpz_init(h3_input_mpz);
    mpz_import(h3_input_mpz, A_size + B_size + C_size + ciphertext->D_size, 1, 1, 0, 0, h3_input);

    anon_proxy_h3(params, h3_input_mpz, h3_output);

    mpz_mul(ciphertext->S, h3_output, r);
    mpz_add(ciphertext->S, ciphertext->S, r_1);
    mpz_mod(ciphertext->S, ciphertext->S, params->q);
}
