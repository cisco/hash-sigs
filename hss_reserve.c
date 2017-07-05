#include <string.h>
#include "common_defs.h"
#include "hss_internal.h"
#include "hss_reserve.h"
#include "endian.h"

/*
 * Initialize the reservation count to the given value
 */
void hss_set_reserve_count(struct hss_working_key *w, sequence_t count) {
    w->reserve_count = count;
}

/*
 * This is called when we generate a signature; it checks if we need
 * to write out a new private key (and advance the reservation)
 */
bool hss_advance_count(struct hss_working_key *w, sequence_t new_count,
        bool (*update_private_key)(unsigned char *private_key,
                size_t len_private_key, void *context),
        void *context) {

    if (new_count > w->reserve_count) {
        /* We need to advance the reservation */
        put_bigendian( w->private_key + PRIVATE_KEY_INDEX, new_count,
                       PRIVATE_KEY_INDEX_LEN );
        if (update_private_key) {
            if (!update_private_key(w->private_key, PRIVATE_KEY_INDEX_LEN,
                                   context)) {
                 /* Oops, we couldn't write the private key; undo the */
                 /* reservation advance (and return an error) */
                 put_bigendian( w->private_key + PRIVATE_KEY_INDEX, w->reserve_count,
                       PRIVATE_KEY_INDEX_LEN );
                return false;
            }
        } else {
            put_bigendian( context, new_count, PRIVATE_KEY_INDEX_LEN );
        }
        w->reserve_count = new_count;
    }

    return true;
}

/*
 * This will make sure that (at least) N signatures are reserved; that is, we
 * won't need to actually call the update function for the next N signatures
 * generated
 *
 * This can be useful if the update_private_key function is expensive.
 *
 * Note that if, N (or more) signatures are already reserved, this won't do
 * anything.
 */
bool hss_reserve_signature(
    struct hss_working_key *w,
    bool (*update_private_key)(unsigned char *private_key,
            size_t len_private_key, void *context),
    void *context,
    unsigned sigs_to_reserve,
    struct hss_extra_info *info) {
    struct hss_extra_info temp_info = { 0 };
    if (!info) info = &temp_info;
    if (!w) {
        info->error_code = hss_error_got_null;
        return false;
    }
    if (w->status != hss_error_none) {
        info->error_code = w->status;;
        return false;
    }

    if (sigs_to_reserve > w->max_count) {
        info->error_code = hss_error_not_that_many_sigs_left;
        return false; /* Very funny */
    }

    /*
     * If we're given a raw private key, make sure it's the one we're
     * thinking of.
     * I have no idea why someone would reserve signatures if they have
     * a raw private key (which is cheap to update), however there's no
     * reason we shouldn't support it
     */
    if (!update_private_key) {
        if (0 != memcmp( context, w->private_key, PRIVATE_KEY_LEN)) {
            info->error_code = hss_error_key_mismatch;
            return false;   /* Private key mismatch */
        }
    }

    /* Figure out what the current count is */
    sequence_t current_count = 0;
    int i;
    for (i = 0; i<w->levels; i++) {
        struct merkle_level *tree = w->tree[i];
            /* -1 because the current_index counts the signatures to the */
            /* current next level */
        current_count = (current_count << tree->level) + tree->current_index - 1;
    }
    current_count += 1;   /* The bottom-most tree isn't advanced */

    sequence_t new_reserve_count;  /* This is what the new reservation */
                     /* setting would be (if we accept the reservation) */
    if (current_count > w->max_count - sigs_to_reserve) {
        /* Not that many sigantures left */
        /* Reserve as many as we can */
        new_reserve_count = w->max_count;
    } else {
        new_reserve_count = current_count + sigs_to_reserve;
    }

    if (new_reserve_count <= w->reserve_count) {
        /* We already have (at least) that many reserved; do nothing */
        return true;
    }

    /* Attempt to update the count in the private key */
    put_bigendian( w->private_key + PRIVATE_KEY_INDEX, new_reserve_count,
                   PRIVATE_KEY_INDEX_LEN );
    /* Update the copy in NV storage */
    if (update_private_key) {
        if (!update_private_key(w->private_key, PRIVATE_KEY_INDEX_LEN, context)) {
             /* Oops, couldn't update it */
             put_bigendian( w->private_key + PRIVATE_KEY_INDEX, w->reserve_count,
                   PRIVATE_KEY_INDEX_LEN );
             info->error_code = hss_error_private_key_write_failed;
             return false;
        }
    } else {
        memcpy( context, w->private_key, PRIVATE_KEY_INDEX_LEN );
    }
    w->reserve_count = new_reserve_count;

    return true;
}
