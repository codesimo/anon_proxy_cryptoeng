#include "elgamal-mod.h"
#include "lib-mesg.h"

/* generazione delle chiavi per uno schema di cifratura Elgamal: possibilità di
 * lavorare nel sottogruppo di ordine primo q e/o di utilizzare precomputazione
 * sulle esponenziazioni a base fissa della cifratura */
void elgamal_mod_init(elgamal_mod_params_t params, size_t lambda, gmp_randstate_t prng)
{
    mpz_t k, a, tmp;

    pmesg(msg_verbose, "generazione chiavi...");

    assert(params);

    assert((lambda == 80) || (lambda == 112) || (lambda == 128));
    assert(prng);

    mpz_inits(k, a, tmp, NULL);
    mpz_inits(params->p, params->q, params->g, params->pk, params->sk, NULL);

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
        mpz_urandomb(params->q, prng, params->q_bits);
    while ((mpz_sizeinbase(params->q, 2) < params->q_bits) ||
           !mpz_probab_prime_p(params->q, elgamal_mr_iterations));

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
             !mpz_probab_prime_p(params->p, elgamal_mr_iterations));

    /* g generatore del sottogruppo di ordine q: g!=1 && g^q=1 */
    pmesg(msg_very_verbose, "utilizzo di un generatore del sottogruppo");
    do
    {
        mpz_urandomm(a, prng, params->p);

        /* g = a^k mod p */
        mpz_powm(params->g, a, k, params->p);

        /* tmp = g^q mod p */
        mpz_powm(tmp, params->g, params->q, params->p);
    } while ((mpz_cmp_ui(params->g, 1) == 0) || (mpz_cmp_ui(tmp, 1) != 0));

    /* esponente segreto x: 2 <= x <= q-1 */
    do
        mpz_urandomm(params->sk, prng, params->q);
    while (mpz_cmp_ui(params->sk, 1) <= 0);

    /* pk = g^sk mod p */
    mpz_powm(params->pk, params->g, params->sk, params->p);

    pmesg_mpz(msg_very_verbose, "modulo", params->p);
    pmesg_mpz(msg_very_verbose, "ordine del sottogruppo", params->q);
    pmesg_mpz(msg_very_verbose, "generatore del sottogruppo", params->g);
    pmesg_mpz(msg_very_verbose, "base pubblica", params->pk);
    pmesg_mpz(msg_very_verbose, "esponente segreto", params->sk);

    mpz_clears(k, a, tmp, NULL);
}

void elgamal_mod_h1(elgamal_mod_params_t params, uint8_t *input, size_t input_size, mpz_t output)
{
    struct elgamal_mod_hash_ctx ctx;
    elgamal_mod_hash_ctx_init(&ctx);
    elgamal_mod_hash_ctx_update(&ctx, input_size, input);

    uint8_t buffer[elgamal_mod_hash_size];
    elgamal_mod_hash_ctx_digest(&ctx, elgamal_mod_hash_size, buffer);

    mpz_import(output, elgamal_mod_hash_size, 1, sizeof(uint8_t), 0, 0, buffer);
    mpz_mod(output, output, params->q);
    // If 0, set to 1
    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void elgamal_mod_h2(elgamal_mod_params_t params, uint8_t *input, size_t input_size, uint8_t *output)
{
    struct elgamal_mod_hash_ctx ctx;
    elgamal_mod_hash_ctx_init(&ctx);

    elgamal_mod_hash_ctx_update(&ctx, elgamal_mod_hash_size, input);

    elgamal_mod_hash_ctx_digest(&ctx, elgamal_mod_ske_key_size, output);
}

void elgamal_mod_encrypt(elgamal_mod_params_t params, gmp_randstate_t prng, elgamal_plaintext_t plaintext, elgamal_ciphertext_t ciphertext)
{
    mpz_t r;
    mpz_init(r);
    do
    {
        mpz_urandomm(r, prng, params->q);
    } while (mpz_cmp_ui(r, 0) == 0);

    size_t q_bytes = params->q_bits / 8;
    size_t r_bytes = q_bytes + plaintext->m_size;

    uint8_t r_in_bytes[r_bytes];
    // FIXME
    mpz_export(r_in_bytes, NULL, 1, 1, 1, 0, r);

    memcpy(r_in_bytes + q_bytes, plaintext->m, plaintext->m_size);

    mpz_t h1_res;
    mpz_init(h1_res);
    elgamal_mod_h1(params, r_in_bytes, r_bytes, h1_res);
    mpz_powm(ciphertext->c1, params->g, h1_res, params->q);

    mpz_t h1_input;
    mpz_init(h1_input);
    mpz_powm(h1_input, params->pk, h1_res, params->q);

    uint8_t h2_res[elgamal_mod_ske_key_size];
    elgamal_mod_h2(params, plaintext->m, plaintext->m_size, h2_res);

    elgamal_mod_ske_set_encypt_key(&(params->ske_ctx), h2_res);
    uint8_t ctr[elgamal_mod_ske_block_size] = {0};

    ciphertext->c2 = (uint8_t *)malloc(plaintext->m_size);
    ciphertext->c2_size = plaintext->m_size;

    //elgamal_mod_ske_block_encrypt(&(params->ske_ctx), (nettle_cipher_func *)elgamal_mod_ske_encrypt, elgamal_mod_ske_block_size, ctr, , ciphertext->c2, h2_res_in_bytes);

    // mpz_clears(r, tmp, NULL);
}
