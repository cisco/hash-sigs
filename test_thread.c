/*
 * This tests out the threading capability
 */

#include "test_hss.h"
#include "hss.h"
#include "hss_thread.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* This will do an initial check if threading is enabled */
/* If it's not, there's no point in these tests */
bool check_threading_on(bool fast_flag) {
    struct thread_collection *col = hss_thread_init(2);
    hss_thread_done(col);

    if (!col) {
        printf( "  Threading not enabled - test skipped\n" );
        return false;
    }
    return true;
}

static int rand_val = 0x01;
static bool rand_1( void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = rand_val + len;
    return true;
}

static bool read_private_key(unsigned char *private_key,
                             size_t len_private_key, void *context) {
    unsigned char **p = context;
    if (!*p) return false;

    memcpy( private_key, *p, len_private_key );
    return true;
}

static bool update_private_key(unsigned char *private_key,
                             size_t len_private_key, void *context) {
    unsigned char **p = context;
    if (!*p) return false;

    memcpy( *p, private_key, len_private_key );
    return true;
}

#define MAX_THREAD 16

bool run_test(unsigned L, const param_set_t *lm, const param_set_t *ots) {
    struct hss_extra_info info[MAX_THREAD];
    int i;

    for (i=0; i<MAX_THREAD; i++) {
        hss_init_extra_info( &info[i] );
        hss_extra_info_set_threads( &info[i], i+1 );
    }

    rand_val++;

    size_t private_len = hss_get_private_key_len(L, lm, ots);
    size_t public_len = hss_get_public_key_len(L, lm, ots);
    size_t sig_len = hss_get_signature_len(L, lm, ots);
#define aux_len 1000
    if (private_len == 0 || private_len > HSS_MAX_PRIVATE_KEY_LEN ||
        public_len == 0 || public_len > HSS_MAX_PUBLIC_KEY_LEN || 
        sig_len == 0) {
        printf( "  Bad parm set\n" );
        return false;
    }

    /* Test out the key creation logic with this parm set */
    unsigned char private[ HSS_MAX_PRIVATE_KEY_LEN ];
    unsigned char public[ HSS_MAX_PUBLIC_KEY_LEN ];
    unsigned char aux[ aux_len ];
    for (i=0; i<MAX_THREAD; i++) {
        unsigned char private_temp[ HSS_MAX_PRIVATE_KEY_LEN ];
        unsigned char public_temp[ HSS_MAX_PUBLIC_KEY_LEN ];
        unsigned char aux_temp[ aux_len ];
        memset( aux_temp, 0, sizeof aux_temp );
        if (!hss_generate_private_key( rand_1,
                    L, lm, ots,
                    0, private_temp,
                    public_temp, sizeof public_temp,
                    aux_temp, sizeof aux_temp,
                    &info[i] )) {
            printf( "  Private key gen failed\n" );
            return false;
        }
        if (i == 0) {
            memcpy( private, private_temp, private_len );
            memcpy( public, public_temp, public_len );
            memcpy( aux, aux_temp, aux_len );
        } else {
            if (0 != memcmp( private, private_temp, private_len )) {
                printf( "  Private key mismatch\n" );
                return false;
            }
            if (0 != memcmp( public, public_temp, public_len )) {
                printf( "  Public key mismatch\n" );
                return false;
            }
            if (0 != memcmp( aux, aux_temp, aux_len )) {
                printf( "  Aux mismatch\n" );
                return false;
            }
        }
    }

    unsigned char *sig = 0;
    unsigned char *sig_temp = 0;

    /* Now, test out the key loading logic */
    bool success_flag = false;
    struct hss_working_key *w[MAX_THREAD] = { 0 };
    unsigned char *current_key = NULL;
    for (i=0; i<MAX_THREAD; i++) {
        current_key = private;
        w[i] = hss_load_private_key( read_private_key, update_private_key, &current_key,
                 0, aux, aux_len, &info[i] );
            current_key = NULL;
        if (!w[i]) {
            printf( "  Load private key failed\n" );
            goto failed;
        }
    }

    int j;
    const unsigned char test_message[] = "Hello spots fans";
    sig = malloc(sig_len);
    sig_temp = malloc(sig_len);
    if (!sig || !sig_temp) goto failed;
   
    for (j=0; j<25; j++) {
        unsigned char private_next[ HSS_MAX_PRIVATE_KEY_LEN ];

        /* Now, test out generating a signature */
        for (i=0; i<MAX_THREAD; i++) {
            unsigned char private_temp[ HSS_MAX_PRIVATE_KEY_LEN ];
            memcpy( private_temp, private, private_len );
            current_key = private_temp;
            if (!hss_generate_signature( w[i],
                     test_message, sizeof test_message, 
                     sig_temp, sig_len,
                     &info[i] )) {
                printf( "  Signature gen failed\n" );
                goto failed;
            }
            current_key = NULL;

            if (i == 0) {
                memcpy( private_next, private_temp, private_len );
                memcpy( sig, sig_temp, sig_len );
            } else {
                if (0 != memcmp( private_next, private_temp, private_len )) {
                    printf( "  Private key update mismatch\n" );
                    goto failed;
                }
                if (0 != memcmp( sig, sig_temp, sig_len )) {
                    printf( "  Signature mismatch\n" );
                    goto failed;
                }
            }
        }
        memcpy( private, private_next, private_len );

        /* Check the validation */
        for (i=0; i<MAX_THREAD; i++) {
            if (!hss_validate_signature( public, 
                         test_message, sizeof test_message,
                         sig, sig_len, &info[i] )) {
                printf( "  Signature validate\n" );
                goto failed;
            }
        }
    }

/* MORE HERE */
    success_flag = true;
failed:
    for (i=0; i<MAX_THREAD; i++) {
        hss_free_working_key( w[i] );
    }
    free(sig);
    free(sig_temp);
    return success_flag;
}

bool test_thread(bool fast_flag, bool quiet_flag) {
    {
        param_set_t lm[1] = { LMS_SHA256_N32_H5 };
        param_set_t ots[1] = { LMOTS_SHA256_N32_W8 };
        if (!run_test(1, lm, ots)) return false;
    }
    {
        param_set_t lm[1] = { LMS_SHA256_N32_H10 };
        param_set_t ots[1] = { LMOTS_SHA256_N32_W4 };
        if (!run_test(1, lm, ots)) return false;
    }
    {
        param_set_t lm[2] = { LMS_SHA256_N32_H10, LMS_SHA256_N32_H5 };
        param_set_t ots[2] = { LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4 };
        if (!run_test(2, lm, ots)) return false;
    }
    if (!fast_flag) { /* This test exceeds our 15 second fast threshold */
        param_set_t lm[2] = { LMS_SHA256_N32_H15, LMS_SHA256_N32_H15 };
        param_set_t ots[2] = { LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W2 };
        if (!run_test(2, lm, ots)) return false;
    }
/* MORE HERE */
    return true;
}
