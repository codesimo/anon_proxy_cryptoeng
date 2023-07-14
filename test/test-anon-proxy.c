#include "lib-anon-proxy.h"
#include "lib-mesg.h"
#include "lib-misc.h"
#include "lib-timing.h"

#define prng_sec_level 128
#define default_message_bytes 32
#define default_lambda anon_proxy_lambda_128

#define bench_sampling_time 5 /* secondi */
#define max_samples (bench_sampling_time * 1000)

int main(int argc, char *argv[])
{
    gmp_randstate_t prng;
    anon_proxy_params_t params;
    anon_proxy_sk_t sk1;
    anon_proxy_pk_t pk1;
    anon_proxy_rekey_t rekey;
    anon_proxy_sk_t sk2;
    anon_proxy_pk_t pk2;
    anon_proxy_plaintext_t msg, msg2;
    anon_proxy_ciphertext_t enc;
    anon_proxy_reencrypted_ciphertext_t reenc;

    char *fixed_msg = NULL; /* default: messaggio causale */
    size_t fixed_msg_len = 0;
    anon_proxy_lambda lambda = default_lambda;
    long prng_seed = -1; /* -1 = seed casuale sicuro */

    bool g_pp = false;
    bool pk_pp = false;

    bool do_bench = false;
    bool do_original = true;
    bool do_proxy = true;
    bool is_verbose = false;

    stats_t timing;
    elapsed_time_t time;
    long int applied_sampling_time = 0;
    int exit_status = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "verbose") == 0)
        {
            set_messaging_level(msg_very_verbose);
            is_verbose = true;
        }
        else if (strcmp(argv[i], "quiet") == 0)
            set_messaging_level(msg_silence);
        else if (strcmp(argv[i], "bench") == 0)
        {
            applied_sampling_time = bench_sampling_time;
            do_bench = true;
        }
        else if (strcmp(argv[i], "all") == 0)
        {
            do_original = true;
            do_proxy = true;
        }
        else if (strcmp(argv[i], "original") == 0)
        {
            do_original = true;
            do_proxy = false;
        }
        else if (strcmp(argv[i], "proxy") == 0)
        {
            do_proxy = true;
            do_original = false;
        }
        else if (strcmp(argv[i], "lambda") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            lambda = atoi(argv[i + 1]);
            if (lambda != anon_proxy_lambda_112 && lambda != anon_proxy_lambda_128 && lambda != anon_proxy_lambda_80)
            {
                printf("lambda non valido!\n");
                exit(1);
            }
            i++;
        }
        else if (strcmp(argv[i], "seed") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            prng_seed = atol(argv[i + 1]);
            if (prng_seed < 0)
            {
                printf("seed non valido!\n");
                exit(1);
            }
            i++;
        }
        else if (strcmp(argv[i], "message") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            fixed_msg = argv[i + 1];
            fixed_msg_len = strlen(fixed_msg);

            i++;
        }
        else if (strcmp(argv[i], "g-pp") == 0)
        {
            g_pp = true;
        }
        else if (strcmp(argv[i], "pk-pp") == 0)
        {
            pk_pp = true;
        }
        else
        {
            printf("utilizzo: %s [verbose|quiet] "
                   "[all|original|proxy] "
                   "[lambda 80|112|128] [seed <n>] [message <n>] [g-pp] [pk-pp] [bench]\n",
                   argv[0]);
            exit(1);
        }
    }
    if (do_bench)
        set_messaging_level(msg_silence);

    printf("Calibrazione strumenti per il timing...\n");
    calibrate_timing_methods();

    printf("\nInizializzazione PRNG ");
    gmp_randinit_default(prng);
    if (prng_seed >= 0)
    {
        printf("(modalità deterministica: seme = %ld)...\n", prng_seed);
        gmp_randseed_ui(prng, (unsigned long int)prng_seed);
    }
    else
    {
        printf("(modalità sicura)...\n");
        gmp_randseed_os_rng(prng, prng_sec_level);
    }

    printf("\nLambda: %d\n", lambda);

    printf("Utilizzo pre-processing  g: %s\n", g_pp ? "true" : "false");
    printf("Utilizzo pre-processing pk: %s\n", pk_pp ? "true" : "false");

    printf("\nGenerazione parametri anon_proxy\n");
    perform_oneshot_cpu_time_sampling(time, tu_millis, {
        anon_proxy_init(params, prng, lambda, g_pp);
    });
    if (do_bench)
        printf_et(" anon_proxy_init: ", time, tu_millis, "\n");

    if (fixed_msg != NULL)
    {
        printf("\nMessaggio fissato...:");
        anon_proxy_plaintext_init_manual(msg, (unsigned char *)fixed_msg, fixed_msg_len);
        if (is_verbose)
        {
            printf("\nMessaggio fissato: ");
            anon_proxy_plaintext_print(stdout, msg);
        }

        printf("\n");
    }
    else
    {
        printf("\nGenerazione messaggio casuale...\n");
        anon_proxy_plaintext_init_random(prng, msg, default_message_bytes);
        if (is_verbose)
        {
            printf("Messaggio casuale: ");
            anon_proxy_plaintext_print(stdout, msg);
        }
    }

    perform_oneshot_cpu_time_sampling(time, tu_millis, {
        anon_proxy_keygen(params, prng, pk_pp, sk1, pk1);
    });
    if (do_bench)
        printf_et(" anon_proxy_keygen: ", time, tu_millis, "\n");

    printf("\nCifratura...\n");
    perform_wc_time_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,
        {
            anon_proxy_encrypt(params, prng, pk1, msg, enc);
            anon_proxy_ciphertext_clear(enc);
        },
        {});
    if (do_bench)
        printf_short_stats(" anon_proxy_encrypt", timing, "");

    anon_proxy_encrypt(params, prng, pk1, msg, enc);
    if (is_verbose)
    {
        printf("Cifratura: ");
        anon_proxy_ciphertext_print(stdout, enc);
    }

    if (do_original)
    {
        printf("\nDecifratura originale...\n");
        perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {
                anon_proxy_decrypt_original(params, sk1, enc, msg2);
                anon_proxy_plaintext_clear(msg2);
            },
            {});
        if (do_bench)
            printf_short_stats(" anon_proxy_decrypt_original", timing, "");

        anon_proxy_decrypt_original(params, sk1, enc, msg2);
        if (is_verbose)
        {
            printf("Decifratura originale: ");
            anon_proxy_plaintext_print(stdout, msg2);
        }

        if (msg->m_size != msg2->m_size || memcmp(msg->m, msg2->m, msg->m_size) != 0)
        {
            printf("Sembra che il processo di decifratura originale non abbia restituito il "
                   "messaggio originale!\n");
            exit_status = 1;
        }
        else
            printf("Decifratura originale tutto ok!\n");
    }

    if (do_proxy)
    {
        printf("\nGenerazione chiavi sk2 e pk2...\n");
        perform_oneshot_cpu_time_sampling(time, tu_millis, {
            anon_proxy_keygen(params, prng, pk_pp, sk2, pk2);
        });
        if (do_bench)
            printf_et(" anon_proxy_keygen: ", time, tu_millis, "\n");

        printf("\nGenerazione chiave di recifratura...\n");
        perform_oneshot_cpu_time_sampling(time, tu_millis, {
            anon_proxy_rekeygen(params, prng, sk1, pk2, rekey);
        });
        if (do_bench)
            printf_et(" anon_proxy_rekeygen: ", time, tu_millis, "\n");

        printf("\nRecifratura...\n");
        perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {
                anon_proxy_reencrypt(params, rekey, enc, reenc);
                anon_proxy_reencrypted_ciphertext_clear(reenc);
            },
            {});
        if (do_bench)
            printf_short_stats(" anon_proxy_reencrypt", timing, "");

        anon_proxy_reencrypt(params, rekey, enc, reenc);
        if (is_verbose)
        {
            printf("Recifratura: ");
            anon_proxy_reencrypted_ciphertext_print(stdout, reenc);
        }

        printf("\nDecifratura messaggio recifrato...\n");
        perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {
                anon_proxy_decrypt_reencrypted(params, sk2, reenc, msg2);
                anon_proxy_plaintext_clear(msg2);
            },
            {});
        if (do_bench)
            printf_short_stats(" anon_proxy_decrypt_reencrypted", timing, "");

        anon_proxy_decrypt_reencrypted(params, sk2, reenc, msg2);
        if (is_verbose)
        {
            printf("Decifratura messaggio recifrato: ");
            anon_proxy_plaintext_print(stdout, msg2);
        }
        if (msg->m_size != msg2->m_size || memcmp(msg->m, msg2->m, msg->m_size) != 0)
        {
            printf("Sembra che il processo di decifratura originale non abbia restituito il "
                   "messaggio originale!\n");
            exit_status = 1;
        }
        else
            printf("Decifratura messaggio recifrato tutto ok!\n");

        anon_proxy_pk_clear(pk2);
        anon_proxy_sk_clear(sk2);
        anon_proxy_rekey_clear(rekey);
        anon_proxy_reencrypted_ciphertext_clear(reenc);
    }

    anon_proxy_pk_clear(pk1);
    anon_proxy_sk_clear(sk1);

    anon_proxy_plaintext_clear(msg);
    anon_proxy_plaintext_clear(msg2);
    anon_proxy_ciphertext_clear(enc);
    anon_proxy_params_clear(params);
    gmp_randclear(prng);
    exit(exit_status);
}
