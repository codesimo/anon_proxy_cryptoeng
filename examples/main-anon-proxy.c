#include "lib-anon-proxy.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_normal);
    anon_proxy_params_t params;
    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 32);
    anon_proxy_init(params, prng, anon_proxy_lambda_80);

    anon_proxy_sk_t sk_1;
    anon_proxy_pk_t pk_1;

    anon_proxy_keygen(params, prng, sk_1, pk_1);

    anon_proxy_plaintext_t plaintext;
    anon_proxy_plaintext_init_random(prng, plaintext, 16);

    pmesg(msg_normal, "\n--------------------------------------------------");
    pmesg_hex(msg_normal, "plaintext", plaintext->m_size, plaintext->m);
    anon_proxy_ciphertext_t ciphertext;

    anon_proxy_encrypt(params, prng, pk_1, plaintext, ciphertext);

    anon_proxy_plaintext_t plaintext2;
    anon_proxy_decrypt_original(params, sk_1, ciphertext, plaintext2);

    assert(plaintext->m_size == plaintext2->m_size);
    assert(memcmp(plaintext->m, plaintext2->m, plaintext->m_size) == 0);

    anon_proxy_sk_t sk_2;
    anon_proxy_pk_t pk_2;
    anon_proxy_keygen(params, prng, sk_2, pk_2);

    anon_proxy_rekey_t rekey;
    anon_proxy_rekeygen(params, prng, sk_1, pk_2, rekey);
    anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext;

    anon_proxy_reencrypt(params, rekey, ciphertext, reencrypted_ciphertext);

    anon_proxy_plaintext_t plaintext3;

    anon_proxy_decrypt_reencrypted(params, sk_2, reencrypted_ciphertext, plaintext3);
    assert(plaintext->m_size == plaintext3->m_size);
    assert(memcmp(plaintext->m, plaintext3->m, plaintext->m_size) == 0);

    return 0;
}