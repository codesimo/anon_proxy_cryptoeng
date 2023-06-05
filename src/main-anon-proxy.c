#include "anon-proxy.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_very_verbose);
    anon_proxy_params_t params;
    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 32);
    anon_proxy_init(params, prng, anon_proxy_lambda_80);

    anon_proxy_sk_t sk;
    anon_proxy_pk_t pk;

    anon_proxy_keygen(params, prng, sk, pk);

    anon_proxy_plaintext_t plaintext;
    plaintext->m_size = 1;
    plaintext->m = malloc(plaintext->m_size);
    memset(plaintext->m, 0, plaintext->m_size);
    for (size_t i = 0; i < plaintext->m_size; i++)
    {
        plaintext->m[i] = i;
    }
    pmesg_hex(msg_verbose, "plaintext", plaintext->m_size, plaintext->m);
    anon_proxy_ciphertext_t ciphertext;

    anon_proxy_encrypt(params, prng, pk, plaintext, ciphertext);

    anon_proxy_plaintext_t plaintext2;
    anon_proxy_decrypt(params, sk, ciphertext, plaintext2, true);

    assert(plaintext->m_size == plaintext2->m_size);
    assert(memcmp(plaintext->m, plaintext2->m, plaintext->m_size) == 0);
    pmesg(msg_verbose, "Tutto ok!");
    return 0;
}