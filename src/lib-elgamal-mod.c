#include <math.h>

#include "lib-elgamal-mod.h"
#include "lib-mesg.h"

/* generazione delle chiavi per uno schema di cifratura Elgamal: possibilità di
 * lavorare nel sottogruppo di ordine primo q e/o di utilizzare precomputazione
 * sulle esponenziazioni a base fissa della cifratura */
void elgamal_mod_init(elgamal_mod_params_t params, elgamal_mod_lambda lambda, gmp_randstate_t prng)
{

    pmesg(msg_verbose, "Initialization...");

    assert(params);

    assert((lambda == 80) || (lambda == 112) || (lambda == 128));
    assert(prng);

    mpz_t k, a, tmp;
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
    {
        mpz_urandomb(params->q, prng, params->q_bits);
    } while ((mpz_sizeinbase(params->q, 2) < params->q_bits) ||
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

    pmesg(msg_verbose, "Initialization completed");
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

void elgamal_mod_h2(uint8_t *input, size_t input_size, uint8_t *output)
{
    struct elgamal_mod_hash_ctx ctx;
    elgamal_mod_hash_ctx_init(&ctx);

    elgamal_mod_hash_ctx_update(&ctx, input_size, input);

    elgamal_mod_hash_ctx_digest(&ctx, elgamal_mod_ske_key_size, output);
}

void elgamal_mod_encrypt(elgamal_mod_params_t params, gmp_randstate_t prng, elgamal_plaintext_t plaintext, elgamal_ciphertext_t ciphertext)
{

    assert(plaintext->m_size % 16 == 0);

    // Random r: 0 < r < q
    mpz_t r;
    mpz_init(r);
    do
    {
        mpz_urandomm(r, prng, params->q);
    } while (mpz_cmp_ui(r, 0) == 0 || mpz_sizeinbase(r, 2) < params->q_bits);

    size_t r_bytes_size = mpz_sizeinbase(r, 256);
    assert(r_bytes_size == params->q_bits / 8);

    // Building r || m
    size_t h1_input_size = r_bytes_size + plaintext->m_size;
    uint8_t h1_in_bytes[h1_input_size];
    memset(h1_in_bytes, 0, h1_input_size);

    size_t x;

    mpz_export(h1_in_bytes, &x, 1, 1, 1, 0, r);
    uint8_t *r_bytes = h1_in_bytes;
    pmesg_hex(msg_verbose, "r", r_bytes_size, r_bytes);

    memcpy(h1_in_bytes + r_bytes_size, plaintext->m, plaintext->m_size);
    pmesg_hex(msg_very_verbose, "r||m", h1_input_size, h1_in_bytes);

    // H1(r||m)
    mpz_t h1_res;
    mpz_init(h1_res);

    elgamal_mod_h1(params, h1_in_bytes, h1_input_size, h1_res);
    pmesg_mpz(msg_very_verbose, "H1(r||m)", h1_res);

    // C1 = g^h1_res mod q
    mpz_powm(ciphertext->c1, params->g, h1_res, params->p);
    pmesg_mpz(msg_verbose, "C1", ciphertext->c1);

    // pk^h1_res mod p
    mpz_t h1_input;
    mpz_init(h1_input);
    mpz_powm(h1_input, params->pk, h1_res, params->p);
    pmesg_mpz(msg_very_verbose, "pk^H1", h1_input);

    // H2(pk^h1_res)
    size_t h2_input_in_bytes = mpz_sizeinbase(h1_input, 256);
    uint8_t h2_input[h2_input_in_bytes];
    memset(h2_input, 0, h2_input_in_bytes);

    mpz_export(h2_input, &x, 1, 1, 1, 0, h1_input);
    assert(x == h2_input_in_bytes);

    uint8_t h2_res[elgamal_mod_ske_key_size];
    memset(h2_res, 0, elgamal_mod_ske_key_size);

    elgamal_mod_h2(h2_input, h2_input_in_bytes, h2_res);

    pmesg_hex(msg_very_verbose, "H2", elgamal_mod_ske_key_size, h2_res);

    // Initialize C2
    ciphertext->c2 = (uint8_t *)malloc(h1_input_size * sizeof(uint8_t));
    ciphertext->c2_size = h1_input_size;

    // Initialize CTR
    uint8_t ctr[elgamal_mod_ske_block_size];
    memset(ctr, 0, elgamal_mod_ske_block_size);

    elgamal_mod_ske_set_encypt_key(&(params->ske_ctx), h2_res);

    // C2 = SKE(H2(pk^h1_res), r||m)
    elgamal_mod_ske_block_encrypt(&(params->ske_ctx),
                                  (nettle_cipher_func *)elgamal_mod_ske_encrypt,
                                  elgamal_mod_ske_block_size,
                                  ctr,
                                  h1_input_size,
                                  ciphertext->c2,
                                  h1_in_bytes);

    pmesg_hex(msg_verbose, "C2", h1_input_size, ciphertext->c2);

    mpz_clears(r, h1_res, h1_input, NULL);
}

void elgamal_mod_decrypt(elgamal_mod_params_t params, elgamal_ciphertext_t ciphertext, elgamal_plaintext_t plaintext)
{
    // C1^sk mod p
    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, ciphertext->c1, params->sk, params->p);
    pmesg_mpz(msg_very_verbose, "C1^sk (H2_input)", h2_input);

    // H2(C1^sk)
    size_t h2_input_size = mpz_sizeinbase(h2_input, 256);
    uint8_t h2_input_bytes[h2_input_size];

    size_t x;
    mpz_export(h2_input_bytes, &x, 1, 1, 1, 0, h2_input);
    assert(x == h2_input_size);

    uint8_t h2_res[elgamal_mod_ske_key_size];
    memset(h2_res, 0, elgamal_mod_ske_key_size);

    elgamal_mod_h2(h2_input_bytes, h2_input_size, h2_res);

    pmesg_hex(msg_very_verbose, "H2", elgamal_mod_ske_key_size, h2_res);

    // r'||m' = SKE.Dec(H2(C1^sk), C2)
    elgamal_mod_ske_set_decrypt_key(&(params->ske_ctx), h2_res);
    uint8_t ctr[elgamal_mod_ske_block_size];
    memset(ctr, 0, elgamal_mod_ske_block_size);

    uint8_t dec_output[ciphertext->c2_size];
    memset(dec_output, 0, ciphertext->c2_size);

    elgamal_mod_ske_block_decrypt(&(params->ske_ctx),
                                  (nettle_cipher_func *)elgamal_mod_ske_decrypt,
                                  elgamal_mod_ske_block_size,
                                  ctr,
                                  ciphertext->c2_size,
                                  dec_output,
                                  ciphertext->c2);

    pmesg_hex(msg_verbose, "r'||m'", ciphertext->c2_size, dec_output);

    // H1(r'||m')
    mpz_t h1_res;
    mpz_init(h1_res);

    elgamal_mod_h1(params, dec_output, ciphertext->c2_size, h1_res);
    pmesg_mpz(msg_very_verbose, "H1(r'||m')", h1_res);

    mpz_powm(h1_res, params->g, h1_res, params->p);

    // C1 =?= g^H1(r'||m')
    assert(mpz_cmp(h1_res, ciphertext->c1) == 0);

    // m = m', r = r'
    plaintext->m_size = ciphertext->c2_size - params->q_bits / 8;
    plaintext->m = (uint8_t *)malloc(plaintext->m_size * sizeof(uint8_t));
    memcpy(plaintext->m, dec_output + params->q_bits / 8, plaintext->m_size);
    uint8_t *r_first = dec_output;
    pmesg_hex(msg_verbose, "r'", params->q_bits / 8, r_first);
    pmesg_hex(msg_verbose, "m'", plaintext->m_size, plaintext->m);

    mpz_clears(h2_input, h1_res, NULL);
}
