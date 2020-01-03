/*
 * This will give a preliminary test of the H=25 case; it's fairly
 * straightforward and is here mostly to say that we actually do test out
 * that case
 *
 * It might make sense to try out the 10/25 and the 25/5 parm sets as well...
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "hss.h"
#include "test_hss.h"

/* This will do an initial check if we're allowed to do H-25 tests */
/* Any test here will take far more than 15 seconds, hence we run them */
/* only in slow mode */
bool check_h25(bool fast_flag) {

    if (fast_flag) {
        printf( "  Not in -full mode - test skipped\n" );
        return false;
    }
    return true;
}

static bool rand_1(void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = len + 1;
    return true;
}

bool test_h25(bool fast_flag, bool quiet_flag) {
    unsigned d = 2;
    param_set_t lm_type[2] = { LMS_SHA256_N32_H25, LMS_SHA256_N32_H25 };
        /* Using the 192 bit parm set on the OTS makes the test go faster */
        /* (and the test takes long enough as it is) */
    param_set_t ots_type[2] = { LMOTS_SHA256_N24_W2, LMOTS_SHA256_N24_W2 };

    /* Simplest test possible */
    int pubkey_size = hss_get_public_key_len( d, lm_type, ots_type );
    int sig_size = hss_get_signature_len( d, lm_type, ots_type );
    int privkey_size = hss_get_private_key_len( d, lm_type, ots_type );
    if (!pubkey_size || pubkey_size > HSS_MAX_PUBLIC_KEY_LEN ||
        !sig_size ||
        !privkey_size || privkey_size > HSS_MAX_PRIVATE_KEY_LEN) {
        printf( "Internal error: bad parm set\n" );
        return false;
    }
    unsigned char pubkey[HSS_MAX_PUBLIC_KEY_LEN];
    unsigned char *sig = malloc(sig_size);
    if (!sig) {
        return false;
    }
    unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];

    unsigned char aux[ 10000 ];

    if (!hss_generate_private_key( rand_1, d, lm_type, ots_type,
                                   NULL, privkey, pubkey, pubkey_size,
                                   aux, sizeof aux, 0)) {
        printf( "Pubkey gen failure\n" );
        free(sig);
        return false;
    }
    if (!quiet_flag) {
        printf( "  Generated public key\n" ); fflush(stdout);
    }

    struct hss_working_key *w = hss_load_private_key(NULL, privkey,
                       100000, aux, sizeof aux, 0 );
    if (!w) {
        printf( "Error loading working key\n" );
        free(sig);
        return false;
    }
    if (!quiet_flag) {
        printf( "  Loaded working key\n" ); fflush(stdout);
    }

    bool retval = true;
    long i;
    for (i=0; i<100000; i++) {
        char message[30];
        sprintf( message, "Message %ld", i );
        unsigned message_len = strlen(message);
        bool success = hss_generate_signature( w, NULL, privkey,
                      message, message_len,
                      sig, sig_size, 0 );

        if (!success) {
            printf( "Error generating signature\n" );
            retval = false;
            break;
        }
 
        if (!hss_validate_signature( pubkey, message, message_len,
                        sig, sig_size, 0 )) {
            printf( "Error validating signature\n" );
            retval = false;
            break;
        }
    }

    hss_free_working_key(w);
    free(sig);
    return retval;
}
