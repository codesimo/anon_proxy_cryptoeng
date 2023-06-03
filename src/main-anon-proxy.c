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
    return 0;
}