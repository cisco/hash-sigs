#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "hss.h"
#include "test_hss.h"


static bool rand_1(void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = len;
    return true;
}

static bool read_private_key(unsigned char *priv_key, size_t len_priv_key, void *context) {
    memcpy( priv_key, context, len_priv_key );
    return true;
}

static bool force_fail = false;

static bool update_private_key(unsigned char *priv_key, size_t len_priv_key, void *context) {
    if (force_fail) return false;
    memcpy( context, priv_key, len_priv_key );
    return true;
}

static bool all_zeros(unsigned char *p, size_t len) {
    while (len--) {
        if (*p++ != '\0') return false;
    }
    return true;
}

static unsigned long get_int(const unsigned char *p) {
    unsigned result = 0;
    int i;
    for (i=0; i<4; i++) {
        result <<= 8;
        result += p[i];
    }
    return result;
}

static int lookup_h(unsigned long val) {
    switch (val) {
    case LMS_SHA256_N32_H5:  return 5;
    case LMS_SHA256_N32_H10: return 10;
    case LMS_SHA256_N32_H15: return 15;
    case LMS_SHA256_N32_H20: return 20;
    case LMS_SHA256_N32_H25: return 25;
    default: return 0;
    }
}

static bool test_parm( int d, long num_sig, ... );

bool test_sign(bool fast_flag, bool quiet_flag) {

    /* Test out various parameter sets */
    if (!test_parm( 1, 32, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W1 )) return false;
    if (!test_parm( 1, 32, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 32, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4 )) return false;
    if (!test_parm( 1, 32, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W8 )) return false;
    if (!test_parm( 1, 1024, LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 2, 1024, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4,
                             LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 32768, LMS_SHA256_N32_H15, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 2, 32768, LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W4,
                             LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 2, 32768, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4,
                             LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 3, 32768, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4,
                             LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4,
                             LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2 )) return false;

    return true;
}

static bool test_parm( int d, long num_sig, ... ) {
    if (d < 1 || d > 8) return false;   /* A different test suite checks that out */

    /* Gather up the parameter set */
    param_set_t lm_type[8];
    param_set_t ots_type[8];

    va_list arg;
    va_start(arg, num_sig);
    int i;
    for (i=0; i<d; i++) {
        lm_type[i] = va_arg( arg, int );
        ots_type[i] = va_arg( arg, int );
    }
    va_end(arg);

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
    if (!sig) return false;
    unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];

    force_fail = false;
    if (!hss_generate_private_key( rand_1, d, lm_type, ots_type,
                                   update_private_key, privkey, pubkey, pubkey_size,
                                   NULL, 0, 0)) {
        printf( "Pubkey gen failure\n" );
        free(sig);
        return false;
    }

    struct hss_working_key *w = hss_load_private_key(read_private_key,
                       update_private_key, privkey,
                       0, NULL, 0, 0 );
    if (!w) {
        printf( "Error loading working key\n" );
        free(sig);
        return false;
    }

    static const unsigned char message[3] = "cde";
    /* Before we start, try various error cases */
    /* We test them more than necessary, however we've set everything these */
    /* failure tests will need, and they don't slow us down much... */
    {
        /* Try to generate a signature with a buffer that's too short */
        struct hss_extra_info info = { 0 };
        bool success = hss_generate_signature( w,
                      message, sizeof message,
                      sig, sig_size-1, &info );
        if (success) {
             printf( "Error: signature succeeded with too small of a buffer\n" );
             hss_free_working_key(w);
             free(sig);
             return false;
        }
        if (hss_extra_info_test_error_code(&info) != hss_error_buffer_overflow) {
             printf( "Error: too small buffer gives wrong error\n" );
             hss_free_working_key(w);
             free(sig);
             return false;
        }
    }

    bool retval = true;
    for (i=0; i<2000; i++) {
        struct hss_extra_info info;
        hss_init_extra_info( &info );
        bool success = hss_generate_signature( w,
                      message, sizeof message,
                      sig, sig_size, &info );

        bool expected_last_sig = (i == num_sig-1);
        bool expected_success = (i <= num_sig-1);
        if (success != expected_success) {
            if (success) {
                printf( "Error: signature succeeded when failute expected\n" );
            } else  {
                printf( "Error generating signature\n" );
            }
            retval = false;
            break;
        }
        if (!success) {
            if (hss_extra_info_test_error_code(&info) != hss_error_private_key_expired) {
                 printf( "Error: private key expiry failure gives wrong error\n" );
                 hss_free_working_key(w);
                 free(sig);
                 return false;
            }
        }
            
        if (hss_extra_info_test_last_signature(&info) != expected_last_sig) {
            printf( "Unexpected last sig\n" );
            retval = false;
            break;
        }
        if (!success) break;
         
        if (!hss_validate_signature( pubkey, message, sizeof message,
                        sig, sig_size, 0 )) {
            printf( "Error validating signature\n" );
            retval = false;
            break;
        }

        /* Scan through the signature to see it has the format we expect; */
        /* chiefly, it uses the expected sequence numbers and the correct */
        /* Merkle parameters for the non-top public keys (which the above */
        /* validate_signature can't check) */
        /* This doesn't validate the hashes (validate_signature did that) */
        /* and it doesn't check if the C values and OTS private keys we */
        /* use aren't always the same (the stats test looks for that); it */
        /* checks everthing else */
        size_t offset = 0; unsigned long val;
#define get_next(val) do { if (offset+4 > sig_size) goto failed; val = get_int( &sig[offset]); offset += 4; } while(0)
        /* Check the number of levels */
        get_next(val); if (val+1 != d) goto failed;

        /* Scan through the signed public keys */
        int level; unsigned long seq_no = 0;
        for (level = 0;; level++) {
            /* Get the q value */
            unsigned long q;
            get_next(q); seq_no += q;   /* We'll make sure that q is in range below */
            /* Get the OTS type */
            get_next(val); if (val != ots_type[level]) goto failed;
            /* Skip the appropriate number of hashes */
            switch (val) {
            case LMOTS_SHA256_N32_W1: offset += 32 + 32*265; break;
            case LMOTS_SHA256_N32_W2: offset += 32 + 32*133; break;
            case LMOTS_SHA256_N32_W4: offset += 32 + 32*67; break;
            case LMOTS_SHA256_N32_W8: offset += 32 + 32*34; break;
            default: goto failed;
            }
            /* Get the LM type */
            get_next(val); if (val != lm_type[level]) goto failed;
            /* Skip the appropriate number of hashes */
            int h = lookup_h(val); if (!h) goto failed;
            offset += 32*h;
            /* Make sure that the q we got was in range */
            if (q >= 1UL << h) goto failed;

            /* If that was the last Merkle signature, stop */
            if (level == d-1) break;

            /* We're now into the public key; validate its parm set */
            get_next(val); if (val != lm_type[level+1]) goto failed;
            h = lookup_h(val); if (!h) goto failed; seq_no <<= h;
            get_next(val); if (val != ots_type[level+1]) goto failed;
            offset += 16 + 32;
        }

        /* If the signature used the wrong sequence number, fail */
        if (seq_no != i) goto failed;

        /* If the signature was too short, fail */
        if (offset != sig_size) goto failed;
    }

    if (i == 2000) {
        struct hss_extra_info info;
        hss_init_extra_info( &info );

        /* Try to generate a signature with a buffer when the update fails */
        /* We do this at the end because it'll advance the current count, */
        /* which would the above test doesn't expect */
        force_fail = true;
        bool success = hss_generate_signature( w,
                      message, sizeof message,
                      sig, sig_size, &info );
        force_fail = false;
        if (success || !all_zeros(sig, sig_size)) {
             printf( "Error: signature succeeded when key update failed\n" );
             hss_free_working_key(w);
             free(sig);
             return false;
        }
        if (hss_extra_info_test_error_code(&info) != hss_error_private_key_write_failed) {
             printf( "Error: update failure gives wrong error\n" );
             hss_free_working_key(w);
             free(sig);
             return false;
        }
    }

    hss_free_working_key(w);
    free(sig);
    return retval;

failed:
    printf( "Signature did not match expected\n" );
    hss_free_working_key(w);
    free(sig);
    return false;
}
