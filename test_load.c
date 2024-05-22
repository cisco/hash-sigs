/*
 * This tests out the key load functionality; this largely focuses on
 * the auxiliary data and various error conditions.
 *
 * The keyload test will do a far more exhaustive test of the non-error case.
 */

#include "test_hss.h"
#include "hss.h"
#include <stdio.h>
#include <stdarg.h>

static bool rand_1( void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = 0x03;
    return true;
}

/*
 * This test is here mainly to verify that we generate the correct
 * working set even if the aux data is corrupted
 */
static bool test_aux( param_set_t lm_setting, param_set_t ots_setting,
                      unsigned hash_len ) {
    int levels = 2;
    param_set_t lm[2];
    lm[0] = lm_setting;
    lm[1] = LMS_SHA256_N24_H5;
    param_set_t ots[2];
    ots[0] = ots_setting;
    ots[1] = LMOTS_SHA256_N32_W2;
    unsigned char priv_key[HSS_MAX_PRIVATE_KEY_LEN];
    unsigned char len_pub_key = hss_get_public_key_len(levels, lm, ots);
    if (!len_pub_key) return false;
    unsigned char pub_key[len_pub_key];
    size_t len_sig = hss_get_signature_len(levels, lm, ots);
    if (!len_sig) return false;
    unsigned char sig[len_sig];

    int i;
    for (i=0; i<2; i++) {
        unsigned aux_size = (i ? 50000 : 500); 
        unsigned char aux_data[aux_size];
        if (!hss_generate_private_key( rand_1, levels, lm, ots,
                                   NULL, priv_key,
                                   pub_key, sizeof pub_key,
                                   aux_data, aux_size, 0)) {
            printf( "Error generating private key\n" );
            return false;
        }

        /* Corrupt the aux data; we corrupt location 36 because that's on */
        /* the aux path of the initial signature; hence if the corruption */
        /* is not detected, the first signature would be wrong */
        aux_data[hash_len+4] ^= 0x01;

        /* Now, load the working key */
        struct hss_working_key *w = hss_load_private_key(
                      NULL, priv_key, 0, aux_data, aux_size, 0);
        if (!w) {
            printf( "Error loading private key\n" );
            return false;
        }

        /* Sign a test message */
        static unsigned char test_message[1] = "a";
        if (!hss_generate_signature(w, NULL, priv_key,
                             test_message, sizeof test_message,
                             sig, sizeof sig, 0)) {
            hss_free_working_key(w);
            printf( "Error generating signature\n" );
            return false;
        }

        /* Verify the signature */
        bool v = hss_validate_signature(pub_key,
                             test_message, sizeof test_message,
                             sig, sizeof sig, 0);
        hss_free_working_key(w);
        if (!v) {
            printf( "Error validating signature from altered aux\n" );
            return false;
        }
    }

    return true;
}

#define NUM_PARM_SETS 11

static bool load_key( int *index, unsigned char priv_key[][48], 
              struct hss_working_key **w, int levels, ...) {
    int i;
    int n = *index;
    if (n == NUM_PARM_SETS) {
        printf( "Internal error: NUM_PARM_SETS too small\n" );
       goto failed;
    }
    if (levels < 1 || levels > 8) {
        printf( "Internal error: bad number of levels\n" );
       goto failed;
    }
    param_set_t lm[8];
    param_set_t ots[8];
    va_list arg;
    va_start(arg, levels);
    for (i=0; i<levels; i++) {
        lm[i] = va_arg( arg, unsigned long );
        ots[i] = va_arg( arg, unsigned long );
    }
    va_end(arg);

    unsigned char pub_key[2000];   /* Actually, we ignore the public key */
    if (!hss_generate_private_key( rand_1, levels, lm, ots,
                                   NULL, priv_key[n],
                                   pub_key, sizeof pub_key, 0, 0, 0)) {
        printf( "Error generating private key\n" );
        goto failed;
    }

    w[n] = allocate_working_key( levels, lm, ots, 0, 0 );
    if (!w[n]) {
        printf( "Error allocating working key\n" );
        goto failed;
    }

    *index = n+1;
    return true;
failed:
    for (i=0; i<NUM_PARM_SETS; i++) {
        hss_free_working_key( w[i] );
        w[i] = NULL;
    }
    return false;
}

bool test_load(bool fast_flag, bool quiet_flag) {

    /*
     * Make sure that various sizes of aux data work consistently
     */
    if (!test_aux( LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2,  32 )) return false;
    if (!test_aux( LMS_SHA256_N24_H5, LMOTS_SHA256_N24_W2,  24 )) return false;
    if (!test_aux( LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W2, 32)) return false;
    if (!test_aux( LMS_SHA256_N24_H10, LMOTS_SHA256_N24_W2, 24)) return false;
    if (!test_aux( LMS_SHA256_N32_H15, LMOTS_SHA256_N32_W2, 32 )) return false;
    if (!test_aux( LMS_SHA256_N24_H15, LMOTS_SHA256_N24_W2, 24 )) return false;
    if (!fast_flag) {
        if (!test_aux( LMS_SHA256_N32_H20, LMOTS_SHA256_N32_W2, 32 )) return false;
        if (!test_aux( LMS_SHA256_N24_H20, LMOTS_SHA256_N24_W2, 24 )) return false;
    }

    /*
     * Verify that we can't load a private key with the wrong parameter set
     * into an already allocated working set
     */
    unsigned char priv_key[NUM_PARM_SETS][48];
    struct hss_working_key *w[NUM_PARM_SETS] = { 0 };

    int index = 0;
    typedef unsigned long ul;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2)) return false;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N32_H10, (ul)LMOTS_SHA256_N32_W2)) return false;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4)) return false;
    if (!load_key( &index, priv_key, w, 2,
                   (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2,
                   (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2)) return false;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2)) return false;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N24_W2)) return false;
    if (!load_key( &index, priv_key, w, 1,
                   (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N24_W4)) return false;
    if (!load_key( &index, priv_key, w, 2,
                   (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2,
                   (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2)) return false;

    int i, j;
    bool retval = true;
    for (i = 0; i<index; i++) {
        for (j=0; j<index; j++) {
            bool expected_success = (i == j);
            struct hss_extra_info info = { 0 };
            bool success = hss_generate_working_key(
                    NULL, priv_key[i], NULL, 0,
                    w[j], &info );
            if (success != expected_success) {
                printf( "Error: for (%d, %d), got success %d\n", i, j, success );
                retval = false;
                goto all_done;  /* No point in trying other things out */
            }
            if (!success && hss_extra_info_test_error_code(&info) !=
                                hss_error_incompatible_param_set) {
                printf( "Error: got wrong error code\n" );
                retval = false;
                goto all_done;  /* No point in trying other things out */
            }
        }
    }

all_done:
    for (i = 0; i<index; i++) hss_free_working_key( w[i] );

    return retval;
}
