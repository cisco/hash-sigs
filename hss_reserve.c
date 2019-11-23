#include <string.h>
#include "common_defs.h"
#include "hss_internal.h"
#include "hss_reserve.h"
#include "endian.h"
#include "hss_fault.h"

/*
 * Initialize the reservation count to the given value
 */
void hss_set_reserve_count(struct hss_working_key *w, sequence_t count) {
    w->reserve_count = count;
}

/*
 * Set the autoreserve count
 */
bool hss_set_autoreserve(struct hss_working_key *w,
            unsigned sigs_to_autoreserve, struct hss_extra_info *info) {
    if (!w) {
        if (info) info->error_code = hss_error_got_null;
        return false;
    }

    /* Note: we do not check if the working key is in a usable state */
    /* There are a couple of odd-ball scenarios (e.g. when they've */
    /* manually allocated the key, but haven't loaded it yet) that we */
    /* don't have a good reason to disallow */

    w->autoreserve = sigs_to_autoreserve;
    return true;
}

/*
 * This is called when we generate a signature; it checks if we hit the
 * end of the current key.
 */
bool hss_check_end_key(struct hss_working_key *w, sequence_t cur_count,
        struct hss_extra_info *info, bool *trash_private_key) {

    if (cur_count == w->max_count) {
        /* We hit the end of what we're allowed to do with this private key */
        /* This will be the last signature this private key can do */
        w->status = hss_error_private_key_expired; /* Fail if they try to */
                                                   /* sign any more */
        info->last_signature = true;
            /* Make sure we zeroize the private key */
        *trash_private_key = true;  /* We can't trash our copy of the */
                /* private key until after we've generated the signature */
                /* We can trash the copy in secure storage, though */
        if (w->update_private_key) {
            unsigned char private_key[PRIVATE_KEY_LEN(MAX_HSS_LEVELS)];
            memset( private_key, 0xff, PRIVATE_KEY_LEN(w->levels) );
            if (!w->update_private_key(private_key, PRIVATE_KEY_LEN(w->levels),
                                       w->context)) {
                info->error_code = hss_error_private_key_write_failed;
                return false;
            }
        } else {
            memset( w->context, 0xff, PRIVATE_KEY_LEN(w->levels) );
        }
    }
    return true;
}

#if FAULT_CACHE_SIG
/*
 * This is called when we advance the reservation; we assume that the hashes
 * currently reflect the state old_count, and we want to update the hashes to
 * reflect new_count.  This will mark any hashes as 'uncomputed' if we haven't
 * computed them yet (in the new_count state).
 * This will return the number of hashes we'll need to write to NVRAM
 */
static int update_cached_sigs_to_reflect_new_count( struct hss_working_key *w,
              sequence_t old_count, sequence_t new_count ) {
    int num_cache_to_update = 0;
    int i, slot;
    sequence_t diff = old_count ^ new_count;
    for (i = w->levels-1, slot=0; i>=0; i--, slot++) {
        struct merkle_level *tree = w->tree[0][i];
        diff >>= tree->level;
        if (diff == 0) break;  /* We use the same sigs from here */

        /* When we switch to the new_count, we'll be using a different */
        /* singature at this level.  We don't know what that is yet, so */
        /* just mark it as TBD */
        memset( w->private_key + PRIVATE_KEY_SIG_CACHE +
                                                 slot*FAULT_CACHE_LEN,
                0, FAULT_CACHE_LEN );
        num_cache_to_update = slot + 1; /* Remember to write it to NVRAM */
    }
    return num_cache_to_update;
}
#endif

/*
 * This is called when we generate a signature; it updates the private
 * key in nvram (if needed), and advances the reservation (again, if needed)
 * If it decides it needs to write out a new private key, it also decides how
 * far it needs to advance it
 */
bool hss_advance_count(struct hss_working_key *w, sequence_t cur_count,
                       struct hss_extra_info *info, int num_sigs_updated) {
    int sigs_to_write = 0;
#if FAULT_CACHE_SIG
    /* Check to see if we've updated a sig that we need to write to NVRAM */
    {
        /* If set, we'll update all the new hashes we have */
        bool force_update = (cur_count > w->reserve_count);
        /* This tells us which hashes the new count uses (as compared to */
        /* the reservation state */
        sequence_t diff = cur_count ^ w->reserve_count;
        int slot;
        for (slot=0; slot<num_sigs_updated; slot++) {
            int i = w->levels - 1 - slot;
            struct merkle_level *tree = w->tree[0][i];
            diff >>= tree->level;
            if (!force_update && diff != 0) {
                continue; /* Nope; at the reservation point, we use a */
                         /* different signature; don't update it */
            }
            /* The cur_count has this new signature, while the current */
            /* reservation state has a previous signature (or none) */
            /* We'll need to update the signature in the private key */
            /* so we can check it later */
            unsigned char *sig_hash = w->private_key + PRIVATE_KEY_SIG_CACHE +
                                                       slot * FAULT_CACHE_LEN;
            hss_set_level(i-1);
            if (!hss_compute_hash_for_cache( sig_hash, w->signed_pk[i],
                                              w->siglen[i-1] )) {
                return false;
            }
            sigs_to_write = slot+1;  /* Make sure we write it */
        }
    }
    /* At this point, the signatures within the private key reflect the */
    /* state at cur_count.  And,  if that differs from the signature state */
    /* at w->reserve_count, then we'll have sigs_to_write > 0 */
#endif

    /*
     * We need to update the NVRAM if either we've gone past what has been
     * previously reserved, or we need to update one of the hashed signatures
     * stored in the NVRAM copy of the private key
     */
    if (cur_count > w->reserve_count || sigs_to_write > 0) {
        /* We need to update the NVRAM */
        sequence_t res_count;   /* The state that we'll write into NVRAM */

        /* Figure out what the new reservation (that is, what we should */
        /* write to NVRAM) should be */
        if (w->max_count - cur_count <= w->autoreserve) {
            /* The autoreservation would go past the end of where we're */
            /* allowed to go - just reserve everything */
            res_count = w->max_count;
        } else if (w->reserve_count < w->autoreserve ||
                   cur_count > w->reserve_count - w->autoreserve) {
            /* The autoreservation based on the current count would go */
            /* past the current reservation */
            res_count = cur_count + w->autoreserve;
        } else {
             /* We're updating the signature hashes we store in the */
              /* private key, but keeping the reservation the same */
            res_count = w->reserve_count;
        }

#if FAULT_CACHE_SIG
        /*
         * The hashed sigs now reflect the state at cur_count; because of
         * autoreservation, we may have advanced things past that.  Update
         * the hashed sigs to reflect the new res_count
         */
        int more_sigs_to_write = update_cached_sigs_to_reflect_new_count( w,
                                                cur_count, res_count );
        if (more_sigs_to_write > sigs_to_write) {
            /* This second update may cause us to rewrite more hashed sigs */
            /* than the original update */
            sigs_to_write = more_sigs_to_write;
        }
#endif

        put_bigendian( w->private_key + PRIVATE_KEY_INDEX, res_count,
                       PRIVATE_KEY_INDEX_LEN );
        enum hss_error_code e = hss_write_private_key( w->private_key, w,
                                                       sigs_to_write );
        if (e != hss_error_none) {
             /* Oops, we couldn't write the private key; undo the */
             /* reservation advance (and return an error) */
             info->error_code = e;
             /* The state of the NVRAM is out of sync with the in-memory */
             /* version.  Instead of trying to fix tihs, throw up our hands */
             /* and mark the entire working state as 'unusable' */
             w->status = e;

             return false;
        }
        w->reserve_count = res_count;
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
    if (!w->update_private_key) {
        if (0 != memcmp( w->context, w->private_key,
                                             PRIVATE_KEY_LEN(w->levels))) {
            info->error_code = hss_error_key_mismatch;
            return false;   /* Private key mismatch */
        }
    }

    /* Figure out what the current count is */
    sequence_t current_count = 0;
    int i;
    for (i = 0; i<w->levels; i++) {
        struct merkle_level *tree = w->tree[0][i];
            /* -1 because the current_index counts the signatures to the */
            /* current next level */
        current_count = (current_count << tree->level) +
                                                  tree->current_index - 1;
#if FAULT_RECOMPUTE
        struct merkle_level *tree_redux = w->tree[1][i];
        if (tree->level != tree_redux->level ||
                  tree->current_index != tree_redux->current_index) {
            return false;  /* Mismatch between primage and redundant trees */
        }
#endif
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

    int num_cache_to_update = 0;
#if FAULT_CACHE_SIG
    num_cache_to_update = update_cached_sigs_to_reflect_new_count(w,
                                     w->reserve_count, new_reserve_count);
#endif

    /* Attempt to update the count in the private key */
    put_bigendian( w->private_key + PRIVATE_KEY_INDEX, new_reserve_count,
                   PRIVATE_KEY_INDEX_LEN );
    /* Update the copy in NV storage */
    enum hss_error_code e = hss_write_private_key(w->private_key, w,
                                                  num_cache_to_update);
    if (e != hss_error_none) {
         /* Oops, couldn't update it */
         info->error_code = e;
         /* The state of the NVRAM is out of sync with the in-memory */
         /* version.  Instead of trying to fix tihs, throw up our hands */
         /* and mark the entire working state as 'unusable' */
         w->status = e;

         return false;
    }
    w->reserve_count = new_reserve_count;

    return true;
}
