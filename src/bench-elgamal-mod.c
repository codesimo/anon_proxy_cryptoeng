#include "elgamal-mod.h"
#include "lib-timing.h"
#include "lib-mesg.h"
#include "lib-misc.h"

#include <string.h>

#include <gmp.h>

int main(int argc, char *argv[])
{
    elapsed_time_t time;
    stats_t stats;
    gmp_randstate_t prng;

    set_messaging_level(msg_silence);
    calibrate_timing_methods();
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 100);

    elgamal_mod_params_t params;
    enum elgamal_mod_lambda lambda = elgamal_mod_lambda_128;
    if (argc > 3)
    {
        printf("Usage: %s [lambda]\n", argv[0]);
        exit(1);
    }
    if (argc == 2)
    {
        if (strcmp(argv[1], "80") == 0 || strcmp(argv[1], "112") == 0 || strcmp(argv[1], "128") == 0)
            lambda = atoi(argv[1]);
        else
        {
            printf("Usage: %s [lambda]\n", argv[0]);
            exit(1);
        }
    }
    printf("Using lambda = %d\n", lambda);

    perform_oneshot_wc_time_sampling(time, tu_millis, {
        elgamal_mod_init(params, lambda, prng);
    });
    printf_et("elgamal_mod_init ", time, tu_millis, "\n");

    elgamal_plaintext_t plaintext;
    plaintext->m_size = 32;
    plaintext->m = (uint8_t *)malloc(plaintext->m_size * sizeof(uint8_t));
    for (size_t i = 0; i < plaintext->m_size; i++)
        plaintext->m[i] = rand() % 256;

    elgamal_ciphertext_t ciphertext;

    perform_wc_time_sampling_period(stats, 10, 10 * 1000, tu_millis, {
        elgamal_mod_encrypt(params, prng, plaintext, ciphertext);
    },
                                    {});
    printf_short_stats("elgamal_mod_encrypt ", stats, "\n");

    elgamal_plaintext_t decrypted;
    perform_wc_time_sampling_period(stats, 10, 10 * 1000, tu_millis, {
        elgamal_mod_decrypt(params, ciphertext, decrypted);
    },
                                    {});
    printf_short_stats("elgamal_mod_decrypt ", stats, "\n");
}