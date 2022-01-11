#include <stdio.h>
#include <stdarg.h>
#include "hss.h"
#include "test_hss.h"


static bool rand_1(void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = len;
    return true;
}

static bool update_fail(unsigned char *priv_key, size_t len_priv_key, void *context) {
    return false;
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
    case LMS_SHA256_N32_H5:
    case LMS_SHA256_N24_H5: return 5;
    case LMS_SHA256_N32_H10:
    case LMS_SHA256_N24_H10: return 10;
    case LMS_SHA256_N32_H15:
    case LMS_SHA256_N24_H15: return 15;
    case LMS_SHA256_N32_H20:
    case LMS_SHA256_N24_H20: return 20;
    case LMS_SHA256_N32_H25:
    case LMS_SHA256_N24_H25: return 25;
    default: return 0;
    }
}

static int lookup_n(unsigned long val) {
    switch (val) {
    case LMS_SHA256_N32_H5:
    case LMS_SHA256_N32_H10:
    case LMS_SHA256_N32_H15:
    case LMS_SHA256_N32_H20:
    case LMS_SHA256_N32_H25:
        return 32;
    case LMS_SHA256_N24_H5:
    case LMS_SHA256_N24_H10:
    case LMS_SHA256_N24_H15:
    case LMS_SHA256_N24_H20:
    case LMS_SHA256_N24_H25:
        return 24;
    default: return 0;
    }
}

static bool test_parm( int d, long num_sig, ... );

bool test_sign(bool fast_flag, bool quiet_flag) {

    /* Test out various parameter sets */
    typedef unsigned long ul;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W1 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W1 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W8 )) return false;
    if (!test_parm( 1, 32, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W8 )) return false;
    if (!test_parm( 1, 1024, (ul)LMS_SHA256_N32_H10, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 1024, (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!test_parm( 1, 1024, (ul)LMS_SHA256_N32_H10, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!test_parm( 1, 1024, (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 2, 1024, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 2, 1024, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!test_parm( 2, 1024, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!test_parm( 2, 1024, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 32768, (ul)LMS_SHA256_N32_H15, (ul)LMOTS_SHA256_N32_W2 )) return false;
    if (!test_parm( 1, 32768, (ul)LMS_SHA256_N24_H15, (ul)LMOTS_SHA256_N24_W2 )) return false;
    if (!fast_flag) {
        if (!test_parm( 2, 32768, (ul)LMS_SHA256_N32_H10, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2 )) return false;
        if (!test_parm( 2, 32768, (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2 )) return false;
        if (!test_parm( 2, 32768, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N32_H10, (ul)LMOTS_SHA256_N32_W2 )) return false;
        if (!test_parm( 2, 32768, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N24_H10, (ul)LMOTS_SHA256_N24_W2 )) return false;
        if (!test_parm( 3, 32768, (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W4,
                             (ul)LMS_SHA256_N32_H5, (ul)LMOTS_SHA256_N32_W2 )) return false;
        if (!test_parm( 3, 32768, (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W4,
                             (ul)LMS_SHA256_N24_H5, (ul)LMOTS_SHA256_N24_W2 )) return false;
    }

    return true;
}

static bool test_parm( int d, long num_sig, ... ) {
    if (d < 1 || d > 8) return false;   /* A different test suite checks */
                                        /* out illegal numbers of levels */

    /* Gather up the parameter set */
    param_set_t lm_type[8];
    param_set_t ots_type[8];

    va_list arg;
    va_start(arg, num_sig);
    int i;
    for (i=0; i<d; i++) {
        lm_type[i] = va_arg( arg, unsigned long );
        ots_type[i] = va_arg( arg, unsigned long );
    }
    va_end(arg);

    /* Simplest test possible */
    int pubkey_size = hss_get_public_key_len( d, lm_type, ots_type );
    int sig_size = hss_get_signature_len( d, lm_type, ots_type );
    int privkey_size = hss_get_private_key_len( d, lm_type, ots_type );
    if (!pubkey_size || !sig_size || !privkey_size) {
        printf( "Internal error: bad parm set\n" );
        return false;
    }
    unsigned char pubkey[pubkey_size];
    unsigned char sig[sig_size];
    unsigned char privkey[privkey_size];

    if (!hss_generate_private_key( rand_1, d, lm_type, ots_type,
                                   NULL, privkey, pubkey, pubkey_size,
                                   NULL, 0, 0)) {
        printf( "Pubkey gen failure\n" );
        return false;
    }

    struct hss_working_key *w = hss_load_private_key(NULL, privkey,
                       0, NULL, 0, 0 );
    if (!w) {
        printf( "Error loading working key\n" );
        return false;
    }

    static const unsigned char message[3] = "cde";
    /* Before we start, try various error cases */
    /* We test them more than necessary, however we've set everything these */
    /* failure tests will need, and they don't slow us down much... */
    {
        /* Try to generate a signature with a buffer that's too short */
        struct hss_extra_info info = { 0 };
        bool success = hss_generate_signature( w, NULL, privkey,
                      message, sizeof message,
                      sig, sig_size-1, &info );
        if (success) {
             printf( "Error: signature succeeded with too small of a buffer\n" );
             hss_free_working_key(w);
             return false;
        }
        if (hss_extra_info_test_error_code(&info) != hss_error_buffer_overflow) {
             printf( "Error: too small buffer gives wrong error\n" );
             hss_free_working_key(w);
             return false;
        }

        /* Try to generate a signature with a buffer when the update fails */
        success = hss_generate_signature( w, update_fail, NULL,
                      message, sizeof message,
                      sig, sig_size, &info );
        if (success || !all_zeros(sig, sig_size)) {
             printf( "Error: signature succeeded when key update failed\n" );
             hss_free_working_key(w);
             return false;
        }
        if (hss_extra_info_test_error_code(&info) != hss_error_private_key_write_failed) {
             printf( "Error: update failure gives wrong error got %d expected %d\n",
		  hss_extra_info_test_error_code(&info), hss_error_private_key_write_failed );
             hss_free_working_key(w);
             return false;
        }
    }

    bool retval = true;
    for (i=0; i<2000; i++) {
        struct hss_extra_info info;
        hss_init_extra_info( &info );
        bool success = hss_generate_signature( w, NULL, privkey,
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
            case LMOTS_SHA256_N24_W1: offset += 24 + 24*200; break;
            case LMOTS_SHA256_N24_W2: offset += 24 + 24*101; break;
            case LMOTS_SHA256_N24_W4: offset += 24 + 24*51; break;
            case LMOTS_SHA256_N24_W8: offset += 24 + 24*26; break;
            default: goto failed;
            }
            /* Get the LM type */
            get_next(val); if (val != lm_type[level]) goto failed;
            /* Skip the appropriate number of hashes */
            int h = lookup_h(val); if (!h) goto failed;
            int n = lookup_n(val); if (!n) goto failed;
            offset += n*h;
            /* Make sure that the q we got was in range */
            if (q >= 1UL << h) goto failed;

            /* If that was the last Merkle signature, stop */
            if (level == d-1) break;

            /* We're now into the public key; validate its parm set */
            get_next(val); if (val != lm_type[level+1]) goto failed;
            h = lookup_h(val); if (!h) goto failed; seq_no <<= h;
            n = lookup_n(val); if (!n) goto failed;
            get_next(val); if (val != ots_type[level+1]) goto failed;
            offset += 16 + n;
        }

        /* If the signature used the wrong sequence number, fail */
        if (seq_no != i) goto failed;

        /* If the signature was too short, fail */
        if (offset != sig_size) goto failed;
    }

    hss_free_working_key(w);
    return retval;

failed:
    printf( "Signature did not match expected\n" );
    printf( "Parameter set under test:\n" );
    for (i=0; i<d; i++) printf( " %x/%x", (unsigned)lm_type[i],
                                          (unsigned)ots_type[i] );
    printf( "\n" );
    hss_free_working_key(w);
    return false;
}
