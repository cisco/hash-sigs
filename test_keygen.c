/*
 * This tests out the key generation API (mostly, various error conditions
 * that it is supposed to catch
 */
#include <stdio.h>
#include <string.h>
#include "hss.h"
#include "test_hss.h"

static size_t got_len;

static bool rand_1(void *output, size_t len) {
    got_len = len;
    unsigned char *p = output;
    while (len--) *p++ = 0x01;
    return true;
}

static bool rand_2(void *output, size_t len) {
    unsigned char *p = output;
    while (len > 1) { len--; *p++ = 0x01; }
    *p++ = 0x03;    /* Last byte is different */
    return true;
}

/* This is a random number generator that failed */
static bool rand_fail(void *output, size_t len) {
    return false;
}

/* This is a filler when we're generating a private key, when we don't */
/* care what the private key is */
static bool ignore_priv_key(unsigned char *priv_key, size_t len_priv_key, void *context) {
    return true;
}

/* This is a function we use to pull in private keys, and record them */
struct priv_key_reader {
    size_t length;
    unsigned char priv_key[100];
};
static bool do_update_priv_key(unsigned char *priv_key, size_t len_priv_key, void *context) {
    struct priv_key_reader *p = context;
    p->length = len_priv_key;
    if (len_priv_key > 100) return false;
    memcpy( p->priv_key, priv_key, len_priv_key);
    return true;
}

static bool update_privkey_fail(unsigned char *priv_key, size_t len_priv_key, void *context) {
    return false;
}

static bool gen_signature( unsigned char *privkey,
               unsigned char *aux_data, size_t aux_len,
               unsigned char *sig, size_t sig_len,
               const unsigned char *pubkey);

bool test_keygen(bool fast_flag, bool quiet_flag) {
        /* We'll use this parameter set, unless we need to test out a different one */
    param_set_t default_lm_type[2] = { LMS_SHA256_N24_H10, LMS_SHA256_N24_H15 };
    param_set_t default_ots_type[2] = { LMOTS_SHA256_N24_W2, LMOTS_SHA256_N24_W8 };
    int default_d = 2;
    int default_pubkey_size = hss_get_public_key_len( default_d, default_lm_type, default_ots_type );
    int default_privkey_size = hss_get_private_key_len( default_d, default_lm_type, default_ots_type );
    if (!default_pubkey_size || default_pubkey_size > HSS_MAX_PUBLIC_KEY_LEN ||
        !default_privkey_size || default_privkey_size > HSS_MAX_PRIVATE_KEY_LEN) {
        printf( "Internal error: bad parm set\n" );
        return false;
    }

    /*
     * First of all, lets try out a good pk gen, just to see if it's
     * basically functional
     */
    {
        unsigned char pubkey[HSS_MAX_PUBLIC_KEY_LEN];
        unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];
        got_len = 0;
        if (!hss_generate_private_key( rand_1,
                     default_d, default_lm_type, default_ots_type,
                     NULL, privkey, pubkey, default_pubkey_size,
                     NULL, 0, 0)) {
            printf( "Initial keygen attempt failed\n" );
            return false;
        }
        /* rand_1 will update got_len */

        /* Make sure we asked the RNG for enough entropy */
        if (got_len < 32) {
            printf( "Requested entropy insufficient\n" );
            return false;
        }

        /*
         * Try it again with the same seed, make sure it generates the same
         * pub/priv key
         */
        unsigned char pubkey_2[HSS_MAX_PUBLIC_KEY_LEN];
        unsigned char privkey_2[HSS_MAX_PRIVATE_KEY_LEN];
        if (!hss_generate_private_key( rand_1,
                     default_d, default_lm_type, default_ots_type,
                     NULL, privkey_2, pubkey_2, default_pubkey_size,
                     NULL, 0, 0)) {
            printf( "Initial keygen attempt failed\n" );
            return false;
        }
        if (0 != memcmp( pubkey, pubkey_2, default_pubkey_size) ||
            0 != memcmp( privkey, privkey_2, default_privkey_size)) {
            printf( "Initial keygen changed with identical seeds\n" );
            return false;
        }

        /* Third time, but with a different seed */
        if (!hss_generate_private_key( rand_2,
                     default_d, default_lm_type, default_ots_type,
                     NULL, privkey_2, pubkey_2, default_pubkey_size,
                     NULL, 0, 0)) {
            printf( "Initial keygen attempt failed\n" );
            return false;
        }
        if (0 == memcmp( pubkey, pubkey_2, default_pubkey_size) ||
            0 == memcmp( privkey, privkey_2, default_privkey_size)) {
            printf( "Initial keygen same with different seeds\n" );
            return false;
        }

        /* Now, try it without a random number generator */
        struct hss_extra_info info;
        hss_init_extra_info( &info );
        if (hss_generate_private_key( NULL,
                    default_d, default_lm_type, default_ots_type,
                    NULL, privkey, pubkey, default_pubkey_size,
                    NULL, 0, &info)) {
            printf( "Keygen successful without random number generator\n" );
            return false;
        }
        if (hss_error_no_randomness!=hss_extra_info_test_error_code(&info)) {
            printf( "No random number generator reported wrong error\n" );
            return false;
        }

        /* Now, try it with a failing random number generator */
        hss_init_extra_info( &info );
        if (hss_generate_private_key( rand_fail,
                   default_d, default_lm_type, default_ots_type,
                   NULL, privkey, pubkey, default_pubkey_size,
                   NULL, 0, &info)) {
            printf( "Keygen successful without random number generator\n" );
            return false;
        }
        if (hss_error_bad_randomness!=hss_extra_info_test_error_code(&info)) {
            printf( "Bad random number generator reported wrong error\n" );
            return false;
        }
    }

    /* Now, we test out various parameter sets (both legal and not) */
    {
        param_set_t lm_type[12], ots_type[12];
        int i;
        for (i=0; i<12; i++) lm_type[i] = LMS_SHA256_N24_H5;
        for (i=0; i<12; i++) ots_type[i] = LMOTS_SHA256_N24_W4;
            /* Since some of these parm sets are illegal (and so don't */
            /* have a size we can look up), we oversize the buffer */

        /* Try various values of levels (both legal and illegal) */
        unsigned char pub_key[ 20000 ];
        size_t len_pub_key = sizeof pub_key;
        int d;
        for (d = 0; d < 12; d++) {
                /* expect_isuccess is true iff we expect the keygen to work */
            bool expect_success = (d >= 1) && (d <= 8);
            struct hss_extra_info info;
            hss_init_extra_info( &info );
            bool got_success = hss_generate_private_key( rand_1,
                              d, lm_type, ots_type,
                              ignore_priv_key, NULL, pub_key, len_pub_key,
                              NULL, 0, &info);
            if (expect_success != got_success) {
                printf( "Keygen with level = %d: success = %d\n", d, got_success );
                return false;
            }
            if (!got_success && hss_extra_info_test_error_code(&info) !=
                                                 hss_error_bad_param_set) {
                printf( "Bad parm set got incorrect error\n" );
                return false;
            }

        }

        d = 3;
        ots_type[0] = LMOTS_SHA256_N24_W2; /* Make the keygen tests faster */
        /* Try various lm_types (both legal and illegal) */
        for (i=0; i<3; i++) {
            param_set_t lm;
            for (lm = 0; lm < 100; lm++)     /* 100???  Well, failure is */
            do {
                      /* quick, so it's not that expensive to test a lot */
                bool expect_success;
                switch (lm) {
                case LMS_SHA256_N32_H5:
                case LMS_SHA256_N32_H10:
                case LMS_SHA256_N32_H15:
                case LMS_SHA256_N24_H5:
                case LMS_SHA256_N24_H10:
                case LMS_SHA256_N24_H15:
                case LMS_SHAKE256_N32_H5:
                case LMS_SHAKE256_N32_H10:
                case LMS_SHAKE256_N32_H15:
                case LMS_SHAKE256_N24_H5:
                case LMS_SHAKE256_N24_H10:
                case LMS_SHAKE256_N24_H15:
                    expect_success = true; break;
                case LMS_SHA256_N32_H20:
                case LMS_SHA256_N24_H20:
                case LMS_SHAKE256_N32_H20:
                case LMS_SHAKE256_N24_H20:
                    if (i == 0 && fast_flag) goto next_iter; /* This parm */
                                        /* set takes too long for fast mode */
                                        /* (20 seconds on my test machine) */
                    expect_success = true; break;
                case LMS_SHA256_N32_H25:
                case LMS_SHA256_N24_H25:
                case LMS_SHAKE256_N32_H25:
                case LMS_SHAKE256_N24_H25:
                    if (i == 0) goto next_iter; /* This parm set takes too */
                                          /* long even for full mode; 10 */
                                          /* minutes for a test that doesn't */
                                          /* tell us much */
                    expect_success = true; break;
                default:   /* All unsupported LM types */
                    expect_success = false; break;
                }
                lm_type[i] = lm;
                struct hss_extra_info info;
                hss_init_extra_info( &info );
                bool got_success = hss_generate_private_key( rand_1,
                                d, lm_type, ots_type,
                                ignore_priv_key, NULL, pub_key, len_pub_key,
                                NULL, 0, &info);
                lm_type[i] = LMS_SHA256_N24_H5;
                if (expect_success != got_success) {
                    printf( "Keygen with lm_type[%d] = %x: success = %d\n",
                                        i, (unsigned)lm, got_success );
                    return false;
                }
                if (!got_success && hss_extra_info_test_error_code(&info) !=
                                                 hss_error_bad_param_set) {
                    printf( "Bad parm set got incorrect error\n" );
                    return false;
                }
next_iter:      lm ^= 0xe0000000L;  /* Cycle through the e000000 parm sets */
           } while (lm & 0x80000000L);
        }
 
        /* Now, try various lm_ots_types (both legal and illegal) */
        for (i=0; i<3; i++) {
            param_set_t ots;
            for (ots = 0; ots < 100; ots++) 
            do {
                bool expect_success;
                switch (ots) {
                case LMOTS_SHA256_N32_W1:
                case LMOTS_SHA256_N32_W2:
                case LMOTS_SHA256_N32_W4:
                case LMOTS_SHA256_N32_W8:
                case LMOTS_SHA256_N24_W1:
                case LMOTS_SHA256_N24_W2:
                case LMOTS_SHA256_N24_W4:
                case LMOTS_SHA256_N24_W8:
                case LMOTS_SHAKE256_N32_W1:
                case LMOTS_SHAKE256_N32_W2:
                case LMOTS_SHAKE256_N32_W4:
                case LMOTS_SHAKE256_N32_W8:
                case LMOTS_SHAKE256_N24_W1:
                case LMOTS_SHAKE256_N24_W2:
                case LMOTS_SHAKE256_N24_W4:
                case LMOTS_SHAKE256_N24_W8:
                    expect_success = true; break;
                default:   /* All unsupported LM types */
                    expect_success = false; break;
                }
                ots_type[i] = ots;
                struct hss_extra_info info;
                hss_init_extra_info( &info );
                bool got_success = hss_generate_private_key( rand_1,
                              d, lm_type, ots_type,
                              ignore_priv_key, NULL, pub_key, len_pub_key,
                              NULL, 0, &info);
                ots_type[i] = LMOTS_SHA256_N24_W4;
                if (expect_success != got_success) {
                    printf( "Keygen with ots_type[%d] = %x: success = %d\n", i, (unsigned)ots, got_success );
                    return false;
                }
                if (!got_success && hss_extra_info_test_error_code(&info) !=
                                                 hss_error_bad_param_set) {
                    printf( "Bad parm set got incorrect error\n" );
                    return false;
                }
                ots ^= 0xe0000000L;  /* Cycle through the e000000 parm sets */
           } while (ots & 0x80000000L);
        } 
    }

    /* Now, test the update private key logic */
    {
        unsigned char pubkey[HSS_MAX_PUBLIC_KEY_LEN];
        unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];

        /* Make sure that if we get the same priv key, whether we use an */
        /* update_private_key function, or if we don't */
        /* Writing the private key to memory */
        if (!hss_generate_private_key( rand_1,
                     default_d, default_lm_type, default_ots_type,
                     NULL, privkey, pubkey, default_pubkey_size,
                     NULL, 0, 0)) {
            printf( "Huh, it worked last time???\n" );
            return false;
        }
        /* Writing the private key to an update function */
        struct priv_key_reader reader;
        if (!hss_generate_private_key( rand_1,
                     default_d, default_lm_type, default_ots_type,
                     do_update_priv_key, &reader, pubkey, default_pubkey_size,
                     NULL, 0, 0)) {
            printf( "Huh, it worked last time???\n" );
            return false;
        }

        /* Was the same key written to both? */
        if (reader.length != default_privkey_size ||
            0 != memcmp( privkey, reader.priv_key, default_privkey_size)) {
            printf( "priv key mismatch\n" );
            return false;
        }

        /* Make sure it fails if the update_priv_key function fails */
        struct hss_extra_info info;
        hss_init_extra_info( &info );
        if (hss_generate_private_key( rand_1,
                    default_d, default_lm_type, default_ots_type,
                    update_privkey_fail, NULL, pubkey, default_pubkey_size,
                    NULL, 0, &info)) {
            printf( "Update privkey failure did not cause failure\n" );
            return false;
        }
        if (hss_extra_info_test_error_code(&info) !=
                              hss_error_private_key_write_failed) {
            printf( "Bad nvwrite got incorrect error\n" );
            return false;
        }

        /* Make sure it fails if we give too short of a pubkey buffer */
        pubkey[ default_pubkey_size-1 ] = 0x5a;
        hss_init_extra_info( &info );
        if (hss_generate_private_key( rand_1,
                    default_d, default_lm_type, default_ots_type,
                    NULL, privkey, pubkey, default_pubkey_size-1,
                    NULL, 0, &info)) {
            printf( "Too short pubkey buffer didn't fail\n" );
            return false;
        }
        if (hss_extra_info_test_error_code(&info) !=
                                             hss_error_buffer_overflow) {
            printf( "Buffer too short got incorrect error\n" );
        }
        if (pubkey[ default_pubkey_size-1 ] != 0x5a) {
            printf( "Buffer overwrite\n" );
            return false;
        }
    }

    /* Check out the aux data, for various parameter sets and lengths of */
    /* aux data */
    int i;
    static param_set_t parms_to_test[] = {
        LMS_SHA256_N32_H5,
        LMS_SHA256_N24_H5,
        LMS_SHA256_N32_H10,
        LMS_SHA256_N24_H10,
        LMS_SHA256_N32_H15,
        LMS_SHA256_N24_H15,
        LMS_SHAKE256_N32_H5,
        LMS_SHAKE256_N24_H5,
        LMS_SHAKE256_N32_H10,
        LMS_SHAKE256_N24_H10,
        LMS_SHAKE256_N32_H15,
        LMS_SHAKE256_N24_H15,
        0,                   /* Stop here if not fastflag */
        LMS_SHA256_N32_H20,
        LMS_SHA256_N24_H20,
        LMS_SHAKE256_N32_H20,
        LMS_SHAKE256_N24_H20,
    };
    for (i=0; i<sizeof parms_to_test/sizeof *parms_to_test; i++) {
        /* In fast mode, don't try the H20 parm set */
        if (parms_to_test[i] == 0) {
            if (fast_flag) break;  /* If we're fast, stop here */
            else continue;         /* If we're not, keep on going */
        }

        param_set_t lm_type[2];
        lm_type[0] = parms_to_test[i]; lm_type[1] = LMS_SHA256_N24_H5;
        param_set_t ots_type[2] = { LMOTS_SHA256_N24_W2, LMOTS_SHA256_N24_W4 };
        int d = 2;

        int pubkey_size = hss_get_public_key_len( d, lm_type, ots_type );
        int sig_size = hss_get_signature_len( d, lm_type, ots_type );
        int privkey_size = hss_get_private_key_len( d, lm_type, ots_type );
        if (!pubkey_size || pubkey_size > HSS_MAX_PUBLIC_KEY_LEN ||
            !sig_size ||
            !privkey_size || privkey_size > HSS_MAX_PRIVATE_KEY_LEN) {
            printf( "Internal error: bad parm set %x\n", (unsigned)lm_type[0] );
            return false;
        }
        unsigned char pubkey[HSS_MAX_PUBLIC_KEY_LEN],
                      pubkey_2[HSS_MAX_PUBLIC_KEY_LEN];
        unsigned char *sig0 = malloc(sig_size);
        unsigned char *sig1 = malloc(sig_size);
        if (!sig0 || !sig1) {
            printf( "Malloc failure\n" );
            return false;
        }
        unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];

        /* Try it with no aux data, and 5 different sizes of aux data */
        if (!hss_generate_private_key( rand_1, d, lm_type, ots_type,
                                       NULL, privkey, pubkey, pubkey_size,
                                       NULL, 0, 0)) {
            printf( "Pubkey gen failure\n" );
            free(sig0); free(sig1);
            return false;
        }

        /* Gen the signature from the private key */
        if (!gen_signature( privkey, NULL, 0, sig0, sig_size, pubkey )) {
            free(sig0); free(sig1);
            return false;
        }

        /* Step through various sizes of aux data; make sure that it */
        /* always works the same */
        unsigned char aux_data[ 100000 ];
        size_t prev_aux_len = 0;
        size_t n;
        for (n = 10; n <= sizeof aux_data; n *= 10) {
            size_t this_aux_len = hss_get_aux_data_len( n, d, lm_type, ots_type );
            if (this_aux_len == prev_aux_len) continue;
            prev_aux_len = this_aux_len;
            if (!hss_generate_private_key( rand_1, d, lm_type, ots_type,
                                       NULL, privkey, pubkey_2, pubkey_size,
                                       aux_data, this_aux_len, 0)) {
                printf( "Pubkey gen failure\n" );
                free(sig0); free(sig1);
                return false;
            }
            if (0 != memcmp( pubkey, pubkey_2, pubkey_size )) {
                printf( "Differing auxlens give varying public keys\n" );
                free(sig0); free(sig1);
                return false;
            }

            /* Gen the signature from the private key */
            if (!gen_signature( privkey, aux_data, this_aux_len, sig1, sig_size, pubkey_2 )) {
                free(sig0); free(sig1);
                return false;
            }

            /* Something's wrong if the signatures differ */
            if (0 != memcmp( sig0, sig1, sig_size )) {
                printf( "Differing auxlens give varying private keys\n" );
                free(sig0); free(sig1);
                return false;
            }
        }
        free(sig0); free(sig1);
    }

    return true;
}

static bool gen_signature( unsigned char *privkey,
               unsigned char *aux_data, size_t aux_len,
               unsigned char *sig, size_t sig_len,
               const unsigned char *pubkey) {
    /* Step 1: load the working key */
    struct hss_extra_info info = { 0 };
    struct hss_working_key *w = hss_load_private_key(NULL, privkey,
                       0, aux_data, aux_len, &info );
    if (!w) {
        printf( "Error loading working key ; error_code = %x\n" , info.error_code);
        return false;
    }

    /* Step 2: use the working key to sign a message */
    static const unsigned char message[3] = "bcd";
    bool success = hss_generate_signature( w, NULL, privkey,
                  message, sizeof message,
                  sig, sig_len, 0 );
    if (!success) {
        printf( "Error generating signature\n" );
    } else if (!hss_validate_signature( pubkey, message, sizeof message,
                    sig, sig_len, 0 )) {
        printf( "Error validating signature\n" );
        success = false;
    }

    hss_free_working_key(w);

    return success;
}
