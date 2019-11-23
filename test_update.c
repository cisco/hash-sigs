/*
 * This tests checks to see if we update the private key when we're supposed
 * to (and as much as we're supposed to
 * The correctness of SIG_CACHE depends on doing this correctly, and so we
 * have a special test for this.  If SIG_CACHE isn't on, this isn't as
 * critical (the update rules are qute simple), however there's no particular
 * reason not to do this test
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include "hss.h"
#include "test_hss.h"

/*
 * These two values are constants based on the config settings
 */
static int size;       /* The base size of the update */
static int increment;  /* The # of bytes of increase for every signed pk */
                       /* we need to update */

static unsigned my_rand_word(void) {
    static uint_fast32_t n = 0;
    n += (n*n) | 5;
    return n >> 16;
}

static bool my_rand(void *output, size_t length) {
    size_t i;
    unsigned char *out = output;
    for (i=0; i<length; i++) {
        *out++ = my_rand_word() & 0xff;
    }
    return true;
}
    

struct update {
    unsigned char pk[ HSS_MAX_PRIVATE_KEY_LEN ];
    int did_update;
    size_t len_update;
};

static bool update_key( unsigned char *private_key, size_t len, void *ctx) {
    struct update *context = ctx;
    if (len > HSS_MAX_PRIVATE_KEY_LEN) return false;
    memcpy( context->pk, private_key, len );
    context->did_update += 1;
    context->len_update = len;
    return true;
}

static bool read_key( unsigned char *private_key, size_t len, void *ctx) {
    struct update *context = ctx;
    if (len > HSS_MAX_PRIVATE_KEY_LEN) return false;
    memcpy( private_key, context->pk, len );
    return true;
}

/*
 * We use H=5 trees everywhere because we're testing what happens if we
 * step between trees; short trees make that happen a lot more often
 */
static param_set_t lm_type[] = {
    LMS_SHA256_N32_H5, LMS_SHA256_N32_H5, LMS_SHA256_N32_H5,
    LMS_SHA256_N32_H5, LMS_SHA256_N32_H5, LMS_SHA256_N32_H5,
    LMS_SHA256_N32_H5, LMS_SHA256_N32_H5,
};

/*
 * W=8???  Doesn't that slow things down?  Well, yes, it does, however the
 * the tests are so fast that it's still a reasonable speed (10 seconds on
 * on my test setup)
 */
static param_set_t ots_type[] = {
    LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W8,
    LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W8,
    LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W8,
};

/*
 * This deduces various sizes of the private key internals (what we update
 * when we just do the sequence number; how much that increases when we also
 * update a signature); these are ultimately based on config.h settings;
 * but we can't just read that file
 */
static bool get_size_increment(void) {
    /* The increment is easy; we have an explicit API for that */
    /* We will double-check it below */
    increment = hss_is_fault_hardening_on( 1 );

    /* The size takes a little more work */

    /* First, create the key */
    struct update context;
    memset( &context, 0, sizeof context );
    unsigned char public_key[ HSS_MAX_PUBLIC_KEY_LEN ];
    unsigned char aux_data[ 500 ];
    bool success = hss_generate_private_key( my_rand, 2, lm_type, ots_type,
                      update_key, &context,
                      public_key, sizeof public_key,
                      aux_data, sizeof aux_data, 0);
    if (!success) return false;

    /* Now, load the key into memory */
    struct hss_working_key *w = hss_load_private_key(
                      read_key, update_key, &context,
                      0, aux_data, sizeof aux_data, 0 );
    if (!w) return false;

    /* Now, generate a signature (and record the size of the update) */
    size_t sig_size = hss_get_signature_len( 2, lm_type, ots_type );
    if (sig_size == 0) { hss_free_working_key(w); return false; }
    void *sig = malloc( sig_size );
    if (!sig) { hss_free_working_key(w); return false; }

    context.did_update = 0;
    if (!hss_generate_signature( w, "abc", 3, sig, sig_size, 0 )) {
        free(sig);
        hss_free_working_key(w);
        return false;
    }

    free(sig);    /* Don't need this buffer anymore */

    if (context.did_update != 1) {
        hss_free_working_key(w);
        return false;
    }

    /* That signature updated the sequene number (and none of the hashes) */
    size = context.len_update;

    /* Now, do a quick double-check, since we're here anyways */
    context.did_update = 0;
    /* Reserving 35 signatures will put us into the next bottom tree, */
    /* requiring us to update that hashed sig */
    if (!hss_reserve_signature( w, 35, 0)) {
        hss_free_working_key(w);
        return false;
    }
    hss_free_working_key(w);    /* Don't need this anymore */

    if (context.did_update != 1 || context.len_update != size + increment ) {
        return false;
    }
    return true;
}

/*
 * This inspects the context structure (which is updated on an NVRAM write)
 * to see if it matches what we're told to expect
 */
static bool check_update_context(const struct update *context,
                                 bool expect_update, int num_hashes_updated) {
    if (!expect_update) {
        /* No updates expected; pass only if we didn't see one */
        return context->did_update == 0;
    } else {
        /* Update expected; verify we got one */
        if (context->did_update != 1) return false;

        /* Verify that it was the expected size */
        if (context->len_update != size + num_hashes_updated * increment ) {
            return false;
        }

        /* Looks good */
        return true;
    }
}

/* This returns the number of places we need to go forward to reach the */
/* next level L epoch (that is, internal Merkle tree) */
static unsigned to_next_step( sequence_t current, int L ) {
    unsigned max = 1U << (5*L);
    return max - (current & (max-1));
}

bool test_update(bool fast_flag, bool quiet_flag) {
    /* Check on what the update size and increment is */
    bool success = get_size_increment();
    if (!success) {
        return false;
    }

    int L;
    bool failed = false;
    /* Step through the possible hss tree levels */
    for (L=1; L<=8; L++) {

        /* Create an HSS tree with L levels (each of which is a height */
        /* 5 tree) */
        struct update context;
        memset( &context, 0, sizeof context );
        unsigned char public_key[ HSS_MAX_PUBLIC_KEY_LEN ];
        unsigned char aux_data[ 500 ];
        bool success = hss_generate_private_key( my_rand, L, lm_type, ots_type,
                      update_key, &context,
                      public_key, sizeof public_key,
                      aux_data, sizeof aux_data, 0);
        if (!success) return false;
        if (context.did_update != 1 || context.len_update !=
                         hss_get_private_key_len( L, lm_type, ots_type )) {
             return false;
        }
            /* The length of the full private key */
        int len_private_key = context.len_update;

        /* Now, load the key into memory */
        context.did_update = 0;
        struct hss_working_key *w = hss_load_private_key(
                      read_key, update_key, &context,
                      0, aux_data, sizeof aux_data, 0 );
        if (!w) return false;
        /* Verify that it did the expected update */
        /* That should have updated if we have SIG_CACHE on *AND* we're */
        /* doing a multilevel tree (single level trees don't have any */
        /* internal signatures) */
        if (!check_update_context( &context, L > 1 && increment > 0, L-1 )) {
            hss_free_working_key(w);
            return false;
        }

        sequence_t current_pos = 0;  /* Our model for the private key's */
                                     /* current position */

        /* Allocate a buffer to hold signatures */
        size_t sig_size = hss_get_signature_len( L, lm_type, ots_type );
        if (sig_size == 0) { hss_free_working_key(w); return false; }
        void *sig = malloc( sig_size );
        if (!sig) { hss_free_working_key(w); return false; }

        int H;
        for (H=0; H<L; H++) {
            /* Verify that we can actually advance between level H trees */
            if (((sequence_t)1 << (5*H)) > UINT_MAX) {
                /* hss_reserve_signature takes an unsigned; on this */
                /* platform, that's not big enough for this iteration */
                break;
            }
            /* Step to right before the next level-H transition */
            int skip = 0;
            if (H > 0) {
                switch (my_rand_word() & 3) {
                case 0: skip =  0; break;
                case 1: skip = 31; break;
                default: skip = my_rand_word() & 0x1f; break;
                }
                unsigned step = to_next_step( current_pos, H ) - (skip+1);
                context.did_update = 0;
                if (!hss_reserve_signature( w, step, 0 )) {
                    failed = true;
                    break;
                }
                if (!check_update_context( &context, step>0, H-1 )) {
                    failed = true;
                    break;
                }
                current_pos += step;

                context.did_update = 0;
                if (!hss_generate_working_key( read_key, update_key, &context,
                                 aux_data, sizeof aux_data, w, 0 )) {
                    failed = true;
                    break;
                }
                if (!check_update_context( &context, H>1, H-1 )) {
                    failed = true;
                    break;
                }
            }

            /* Now, generate 32 signatures; the skip'th one should trigger */
            /* an update of size H */
            int count_sig = 0;
            for (count_sig = 0; count_sig < 32; count_sig++) {
                context.did_update = 0;
                if (!hss_generate_signature( w, "abc", 3, sig, sig_size, 0 )) {
                    failed = true;
                    break;
                }
                if (L == 1 && count_sig == 31) {
                    /* Special case; if we hit the end of the key, we're */
                    /* supposed to overwrite the entire private key */
                    if (context.did_update != 1 ||
                                      context.len_update != len_private_key) {
                        failed = true;
                        break;
                    }
                } else {
                    int expect_write;
                    if (H == 0) {
                        expect_write = (count_sig == 31) ? 1 : 0;
                    } else {
                        expect_write = (count_sig==skip) ? H : 0;
                    }
                    if (!check_update_context( &context, true, expect_write )) {
                        failed = true;
                        break;
                    }
                    current_pos += 1;
                }
            }
            if (failed) break;

            if (L == 1) break;  /* With L=1, we just used up the */
                              /* entire key.  Now, we could regen the key */
                              /* and start over, however that wouldn't test */
                              /* that much more, and so we don't bother */

            /*
             * Now, this rather lengthy section tests our behavior if we
             * step into a tree that is entirely reserved (and makes sure we
             * don't update in that case)
             */ 
            if (H == 0) continue; /* At the bottom, there's no "next tree" */

            /*
             * Now, advance the current_pos so that it is and the end of
             * the current tree
             */
            unsigned step = to_next_step( current_pos, H ) + (1<<(5*H)) -
                                                ((my_rand_word() & 0xf)+1);
            context.did_update = 0;
            if (!hss_reserve_signature( w, step, 0 )) {
                failed = true;
                break;
            }
            if (!check_update_context( &context, true, H )) {
                failed = true;
                break;
            }
            current_pos += step;

            context.did_update = 0;
            if (!hss_generate_working_key( read_key, update_key, &context,
                                 aux_data, sizeof aux_data, w, 0 )) {
                failed = true;
                break;
            }
            if (!check_update_context( &context, true, H )) {
                failed = true;
                break;
            }

            /*
             * Now, advance the current_pos so that it is two trees from now
             */
            step = to_next_step( current_pos, H ) + 2*(1<<(5*H)) +
                                                ((my_rand_word() & 0xf)+1);
            context.did_update = 0;
            if (!hss_reserve_signature( w, step, 0 )) {
                failed = true;
                break;
            }
            if (!check_update_context( &context, true, H )) {
                failed = true;
                break;
            }
            current_pos += step;
            
            /* Now, generate 32 signatures; none of them should trigger an */
            /* update (even though we advance to the next tree) */
            for (count_sig = 0; count_sig < 32; count_sig++) {
                context.did_update = 0;
                if (!hss_generate_signature( w, "abc", 3, sig, sig_size, 0 )) {
                    failed = true;
                    break;
                }
                if (!check_update_context( &context, false, 0 )) {
                     failed = true;
                     break;
                 }
            }

            /* Step to the current position (the next iteration will */
            /* expect us to be current) */
            context.did_update = 0;
            if (!hss_generate_working_key( read_key, update_key, &context,
                                 aux_data, sizeof aux_data, w, 0 )) {
                failed = true;
                break;
            }
            if (!check_update_context( &context, true, H )) {
                failed = true;
                break;
            }
        }

        free(sig);
        hss_free_working_key(w);
        if (failed) return false;
    }

    return true;
}
