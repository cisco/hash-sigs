#include <string.h>
#include "hss.h"
#include "hss_internal.h"
#include "endian.h"
#include "hss_zeroize.h"
#include "lm_common.h"

/*
 * Convert a parameter set into the compressed version we use within a private
 * key.  This is the private key that'll end up being updated constantly, and
 * so we try to make it as small as possible
 */
bool hss_compress_param_set( unsigned char *compressed,
                   int levels, 
                   const param_set_t *lm_type,
                   const param_set_t *lm_ots_type,
                   size_t len_compressed ) {
    int i;

    if (levels > len_compressed) return false;

    for (i=0; i<levels; i++) {
        param_set_t a = *lm_type++;
        param_set_t b = *lm_ots_type++;
            /* All the parameter sets we support are small */
            /* Review this format if we need to support larger ones */
        if (a > 0x0e || b > 0x0e) return false;
            /* Make sure the parm sets are supported */
        switch (a) {
        case LMS_SHA256_N32_H5: case LMS_SHA256_N32_H10:
        case LMS_SHA256_N32_H15: case LMS_SHA256_N32_H20:
        case LMS_SHA256_N32_H25:
            break;
        default:
            return false;
        }
        switch (b) {
        case LMOTS_SHA256_N32_W1: case LMOTS_SHA256_N32_W2:
        case LMOTS_SHA256_N32_W4: case LMOTS_SHA256_N32_W8:
            break;
        default:
            return false;
        }
        
        *compressed++ = (a<<4) + b;
        len_compressed--;
    }

    return true;
}

/*
 * This returns the parameter set for a given private key.
 * This is here to solve a chicken-and-egg problem: the hss_working_key
 * must be initialized to the same parameter set as the private key,
 * but (other than this function, or somehow remembering it) there's
 * no way to retreive the parameter set.
 *
 * read_private_key/context will read the private key (if read_private_key is
 * NULL, context is assumed to point to the private key)
 *
 * On success, *levels will be set to the number of levels, and lm_type[]
 * and lm_ots_type[] will be set to the lm/ots parameter sets
 *
 * On success, this returns true; on failure (can't read the private key, or
 * the private key is invalid), returns false 
 */
bool hss_get_parameter_set( unsigned *p_levels,
                           param_set_t lm_type[ MAX_HSS_LEVELS ],
                           param_set_t lm_ots_type[ MAX_HSS_LEVELS ],
                           bool (*read_private_key)(unsigned char *private_key,
                                       size_t len_private_key, void *context),
                           void *context,
                           struct hss_extra_info *info) {
    enum hss_error_code temp_error, *error;
    if (info) {
        error = &info->error_code;
    } else {
        error = &temp_error;
    }
    unsigned char private_key[ HSS_MAX_PRIVATE_KEY_LEN ];
    bool success = false;
    unsigned levels;

    if (read_private_key) {
        if (!read_private_key( private_key,
                   PRIVATE_KEY_FORMAT + PRIVATE_KEY_FORMAT_LEN, context) ||
            (levels = private_key[PRIVATE_KEY_FORMAT_NUM_LEVEL]) < 1 ||
            levels > MAX_HSS_LEVELS ||
             !read_private_key( private_key,
                     PRIVATE_KEY_LEN(levels), context)) {
            *error = hss_error_private_key_read_failed;
            goto failed;
        }
    } else {
        if (!context) {
            *error = hss_error_no_private_buffer;
            return false;
        }
        levels = ((unsigned char*)context)[PRIVATE_KEY_FORMAT_NUM_LEVEL];
        if (levels < 1 || levels > MAX_HSS_LEVELS) {
             *error = hss_error_bad_private_key;
             goto failed;
        }
        memcpy( private_key, context, PRIVATE_KEY_LEN(levels) );
    }
    if (!hss_check_private_key(private_key)) {
         *error = hss_error_bad_private_key;
         goto failed;
    }

    /* Scan through the private key to recover the parameter sets */
    unsigned total_height = 0;
    unsigned level;
    for (level=0; level < levels; level++) {
        unsigned char c = private_key[PRIVATE_KEY_PARAM_SET(levels) + level];
            /* Decode this level's parameter set */
        param_set_t lm = (c >> 4);
        param_set_t ots = (c & 0x0f);
            /* Make sure both are supported */
            /* While we're here, add up the total Merkle height */
        switch (lm) {
        case LMS_SHA256_N32_H5:  total_height += 5; break;
        case LMS_SHA256_N32_H10: total_height += 10; break;
        case LMS_SHA256_N32_H15: total_height += 15; break;
        case LMS_SHA256_N32_H20: total_height += 20; break;
        case LMS_SHA256_N32_H25: total_height += 25; break;
        default:
             *error = hss_error_bad_private_key;
             goto failed;
        }
        switch (ots) {
        case LMOTS_SHA256_N32_W1:
        case LMOTS_SHA256_N32_W2:
        case LMOTS_SHA256_N32_W4:
        case LMOTS_SHA256_N32_W8:
             break;
        default:
             *error = hss_error_bad_private_key;
             goto failed;
        }
        lm_type[level] = lm;
        lm_ots_type[level] = ots;
    }

    *p_levels = levels;

    /* One final check; make sure that the sequence number listed in the */
    /* private key is in range */

    if (total_height > 64) total_height = 64; /* (bounded by 2**64) */
    sequence_t max_count = ((sequence_t)2 << (total_height-1)) - 1;
        /* height-1 so we don't try to shift by 64, and hit U.B. */

        /* We use the count 0xffff..ffff to signify 'we've used up all our */
        /* signatures'.  Make sure that is above max_count, even for */
        /* parameter sets that can literally generate 2**64 signatures (by */
        /* letting them generate only 2**64-1) */
    if (total_height == 64) max_count--;
    sequence_t current_count = get_bigendian(
                 private_key + PRIVATE_KEY_INDEX, PRIVATE_KEY_INDEX_LEN );

    if (current_count > max_count) {
        *error = hss_error_private_key_expired;
        goto failed;
    }

    success = true;   /* It worked! */
failed:
        /* There might be private keying material here */
    hss_zeroize( private_key, sizeof private_key );
    return success;
}

/* Compute the max number of signatures we can generate */
sequence_t hss_get_max_seqno( int levels, const param_set_t *lm_type ) {
    int total_height = 0;
    int i;

    for (i=0; i<levels; i++) {
        unsigned this_height;
        if (!lm_look_up_parameter_set(lm_type[i], 0, 0, &this_height )) {
            return 0;
        }
        total_height += this_height;
    }

    if (total_height > 64) total_height = 64;  /* (bounded by 2**64) */

    sequence_t max_seqno = ((sequence_t)2 << (total_height-1)) - 1;
        /* height-1 so we don't try to shift by 64, and hit undefined */
        /* behavior */

    /* We use the count 0xffff..ffff to signify 'we've used up all our */
    /* signatures'.  Make sure that is above max_count, even for */
    /* parameter sets that can literally generate 2**64 signatures (by */
    /* letting them generate only 2**64-1) */
    if (total_height == 64) max_seqno--;

    return max_seqno;
}

