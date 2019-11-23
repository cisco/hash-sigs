#include <stdlib.h>
#include <string.h>
#include "common_defs.h"
#include "hss.h"
#include "hss_internal.h"
#include "hss_aux.h"
#include "endian.h"
#include "hash.h"
#include "hss_thread.h"
#include "lm_common.h"
#include "lm_ots_common.h"
#include "hss_fault.h"

/* Count the number of 1 bits at the end (lsbits) of the integer */
/* Do it in the obvious way; straightline code may be faster (no */
/* unpredictable jumps, which are costly), but that would be less scrutable */
static int trailing_1_bits(merkle_index_t n) {
    int i;
    for (i=0; n&1; n>>=1, i++)
        ;
    return i;
}

/*
 * This creates a private key (and the correspond public key, and optionally
 * the aux data for that key)
 * Parameters:
 * generate_random - the function to be called to generate randomness.  This
 *       is assumed to be a pointer to a cryptographically secure rng,
 *       otherwise all security is lost.  This function is expected to fill
 *       output with 'length' uniformly distributed bits, and return 1 on
 *       success, 0 if something went wrong
 * levels - the number of levels for the key pair (2-8)
 * lm_type - an array of the LM registry entries for the various levels;
 *      entry 0 is the topmost
 * lm_ots_type - an array of the LM-OTS registry entries for the various
 *      levels; again, entry 0 is the topmost
 * update_private_key, context - the function that is called when the
 *      private key is generated; it is expected to store it to secure NVRAM
 *      If this is NULL, then the context pointer is reinterpretted to mean
 *      where in RAM the private key is expected to be placed
 * public_key - where to store the public key
 * len_public_key - length of the above buffer; see hss_get_public_key_len
 *      if you need a hint.
 * aux_data - where to store the optional aux data.  This is not required, but
 *      if provided, can be used to speed up the hss_generate_working_key
 *      process;
 * len_aux_data - the length of the above buffer.  This is not fixed length;
 *      the function will run different time/memory trade-offs based on the
 *      length provided
 *
 * This returns true on success, false on failure
 */
bool hss_generate_private_key(
    bool (*generate_random)(void *output, size_t length),
    unsigned levels,
    const param_set_t *lm_type,
    const param_set_t *lm_ots_type,
    bool (*update_private_key)(unsigned char *private_key,
            size_t len_private_key, void *context),
        void *context,
    unsigned char *public_key, size_t len_public_key,
    unsigned char *aux_data, size_t len_aux_data,
    struct hss_extra_info *info) {

    struct hss_extra_info info_temp = { 0 };
    if (!info) info = &info_temp;

    if (!generate_random) {
        /* We *really* need random numbers */
        info->error_code = hss_error_no_randomness;
        return false;
    }
    if (levels < MIN_HSS_LEVELS || levels > MAX_HSS_LEVELS) {
        /* parameter out of range */
        info->error_code = hss_error_bad_param_set;
        return false;
    }

    unsigned h0;  /* The height of the root tree */
    unsigned h;   /* The hash function used */
    unsigned size_hash;  /* The size of each hash that would appear in the */
                  /* aux data */
    if (!lm_look_up_parameter_set(lm_type[0], &h, &size_hash, &h0)) {
        info->error_code = hss_error_bad_param_set;
        return false;
    }

    /* Check the public_key_len */
    if (4 + 4 + 4 + I_LEN + size_hash > len_public_key) {
        info->error_code = hss_error_buffer_overflow;
        /* public key won't fit in the buffer we're given */
        return false;
    }

        /* If you provide an aux_data buffer, we have to write something */
        /* into it (at least, enough to mark it as 'we're not really using */
        /* aux data) */
    if (aux_data && len_aux_data == 0) {
        /* not enough aux data buffer to mark it as 'not really used' */
        info->error_code = hss_error_bad_aux;
        return false;
    }

    unsigned len_ots_pub = lm_ots_get_public_key_len(lm_ots_type[0]);
    if (len_ots_pub == 0) {
        info->error_code = hss_error_bad_param_set;
        return false;
    }

    unsigned char private_key[ PRIVATE_KEY_LEN(MAX_HSS_LEVELS) ];

        /* First step: format the private key */
    hss_set_private_key_format( private_key, levels );
    put_bigendian( private_key + PRIVATE_KEY_INDEX, 0,
                   PRIVATE_KEY_INDEX_LEN );
#if FAULT_CACHE_SIG
        /* Mark all signatures as "not computed yet" */
    memset( private_key + PRIVATE_KEY_SIG_CACHE, 0,
            PRIVATE_KEY_SIG_CACHE_LEN(levels) );
#endif
    if (!hss_compress_param_set( private_key + PRIVATE_KEY_PARAM_SET(levels),
                   levels, lm_type, lm_ots_type,
                   PRIVATE_KEY_PARAM_SET_LEN(levels) )) {
        info->error_code = hss_error_bad_param_set;
        return false;
    }
        /* Fill in the maximum seqno */
    sequence_t max_seqno = hss_get_max_seqno( levels, lm_type );
    if (max_seqno == 0) {
        info->error_code = hss_error_bad_param_set;
        return false;
    }
    put_bigendian( private_key + PRIVATE_KEY_MAX(levels), max_seqno,
                   PRIVATE_KEY_MAX_LEN );

        /* Pick the random seed */
    if (!(*generate_random)( private_key + PRIVATE_KEY_SEED(levels),
                   PRIVATE_KEY_SEED_LEN )) {
        info->error_code = hss_error_bad_randomness;
        return false;
    }

        /* Now make sure that the private key is written to NVRAM */
    if (!update_private_key && !context) {
        /* We weren't given anywhere to place the private key */
        info->error_code = hss_error_no_private_buffer;
        hss_zeroize( private_key, sizeof private_key );
        return false;
    }
    enum hss_error_code e = hss_write_private_key_no_w( private_key,
                  PRIVATE_KEY_LEN(levels), 0, update_private_key, context );
    if (e != hss_error_none) {
        info->error_code = e;
        hss_zeroize( private_key, sizeof private_key );
        return false;
    }

    /* Figure out what would be the best trade-off for the aux level */
    struct expanded_aux_data *expanded_aux_data = 0, aux_data_storage;
    if (aux_data != NULL) {
        aux_level_t aux_level = hss_optimal_aux_level( len_aux_data, lm_type,
                                       lm_ots_type, NULL );
        hss_store_aux_marker( aux_data, aux_level );

        /* Set up the aux data pointers */
        expanded_aux_data = hss_expand_aux_data( aux_data, len_aux_data,
                                    &aux_data_storage, size_hash, 0 );
    }

    unsigned char I[I_LEN];
    unsigned char seed[SEED_LEN];
    if (!hss_generate_root_seed_I_value( seed, I, private_key+PRIVATE_KEY_SEED(levels),
                                    lm_type[0], lm_ots_type[0])) {
        info->error_code = hss_error_internal;
        hss_zeroize( private_key, sizeof private_key );
        return false;
    }

    /* Now, it's time to generate the public key, which means we need to */
    /* compute the entire top level Merkle tree */

    /* First of all, figure out the appropriate level to compute up to */
    /* in parallel.  We'll do the lower of the bottom-most level that */
    /* appears in the aux data, and 4*log2 of the number of core we have */
    unsigned num_cores = hss_thread_num_tracks(info->num_threads);
    unsigned level;
    for (level = h0-1; level > 0; level--) {
            /* If our bottom-most aux data is at this level, we want it */
        if (expanded_aux_data && expanded_aux_data->data[level]) break;

            /* If going to a higher levels would mean that we wouldn't */
            /* effectively use all the cores we have, use this level */ 
        if ((1<<level) < 4*num_cores) break;
    }

    /* Get the buffer where our parallel process is going to write into */
    /* We'll either use the aux data itself, or a temp buffer */
    unsigned temp_buffer_size;
    unsigned char *dest;
    if (expanded_aux_data && expanded_aux_data->data[level]) {
        /* We're going directly into the aux data */
        dest = expanded_aux_data->data[level];
        temp_buffer_size = 1;  /* We're not using the temp buffer */
     } else {
        /* We're going into the temp buffer */
        dest = 0;
        temp_buffer_size = (size_t)size_hash << level;
    }
    unsigned char temp_buffer[ temp_buffer_size ];
    if (!dest) dest = temp_buffer;

    /*
     * Now, issue all the work items to generate the intermediate hashes
     * These intermediate passes are potentially computed in parallel;
     * allowing that is why we use this funky thread_collection and details
     * structure
     */
    struct thread_collection *col = hss_thread_init(info->num_threads);

    struct intermed_tree_detail details;
        /* Set the values in the details structure that are constant */
    details.level = 0;
    details.seed = seed;
    details.lm_type = lm_type[0];
    details.lm_ots_type = lm_ots_type[0];
    details.h = h;
    details.tree_height = h0;
    details.I = I;
    enum hss_error_code got_error = hss_error_none;  /* This flag is set */
                                                     /* on an error */
    details.got_error = &got_error;

    merkle_index_t j;
        /* # of nodes at this level */
    merkle_index_t level_nodes = (merkle_index_t)1 << level;
        /* the index of the node we're generating right now */
    merkle_index_t node_num = level_nodes;
        /*
         * We'd prefer not to issue a separate work item for every node; we
         * might be doing millions of node (if we have a large aux data space)
         * and we end up malloc'ing a large structure for every work order.
         * So, if we do have a large number of requires, aggregate them
         */
    merkle_index_t increment = level_nodes / (10 * num_cores);
#define MAX_INCREMENT 20000
    if (increment > MAX_INCREMENT) increment = MAX_INCREMENT;
    if (increment == 0) increment = 1;
    for (j=0; j < level_nodes; ) {
        unsigned this_increment;
        if (level_nodes - j < increment) {
            this_increment = level_nodes - j;
        } else {
            this_increment = increment;
       }

        /* Set the particulars of this specific work item */
        details.dest = dest + j*size_hash;
        details.node_num = node_num;
        details.node_count = this_increment;

        /* Issue a separate work request for every node at this level */
        hss_thread_issue_work(col, hss_gen_intermediate_tree,
                              &details, sizeof details );

        j += this_increment;
        node_num += this_increment;
    }
    /* Now wait for all those work items to complete */
    hss_thread_done(col);

    hss_zeroize( seed, sizeof seed );

    /* Check if something went wrong.  It really shouldn't have, however if */
    /* something returns an error code, we really should try to handle it */
    if (got_error != hss_error_none) {
        /* We failed; give up */
        info->error_code = got_error;
        hss_zeroize( private_key, sizeof private_key );
        if (update_private_key) {
            (void)(*update_private_key)(private_key, PRIVATE_KEY_LEN(levels),
                                                                  context);
        } else {
            hss_zeroize( context, PRIVATE_KEY_LEN(levels) );
        }
        return false;
    }

    /* Now, we complete the rest of the tree.  This is actually fairly fast */
    /* (one hash per node) so we don't bother to parallelize it */

    unsigned char stack[ MAX_HASH * (MAX_MERKLE_HEIGHT+1) ];
    unsigned char root_hash[ MAX_HASH ];

    /* Generate the top levels of the tree, ending with the root node */
    merkle_index_t r, leaf_node;
    hss_set_level(0);
    for (r=level_nodes, leaf_node = 0; leaf_node < level_nodes; r++, leaf_node++) {

        /* Walk up the stack, combining the current node with what's on */
        /* the atack */
        merkle_index_t q = leaf_node;

        /*
         * For the subtree which this leaf node forms the final piece, put the
         * destination to where we'll want it, either on the stack, or if this
         * is the final piece, to where the caller specified
         */
        unsigned char *current_buf;
        int stack_offset = trailing_1_bits( leaf_node );
        if (stack_offset == level) {
            current_buf = root_hash;
        } else {
            current_buf = &stack[stack_offset * size_hash ];
        }
        memcpy( current_buf, dest + leaf_node * size_hash, size_hash );

        unsigned sp;
        unsigned cur_lev = level;
        for (sp = 1;; sp++, cur_lev--, q >>= 1) {
            /* Give the aux data routines a chance to save the */
            /* intermediate value.  Note that we needn't check for the */
            /* bottommost level; if we're saving aux data at that level, */
            /* we've already placed it there */
            if (sp > 1) {
                hss_save_aux_data( expanded_aux_data, cur_lev,
                                   size_hash, q, current_buf );
            }

            if (sp > stack_offset) break;


            hss_combine_internal_nodes( current_buf,
                            &stack[(sp-1) * size_hash], current_buf,
                            h, I, size_hash,
                            r >> sp );
        }
    }
    /* The top entry in the stack is the root value (aka the public key) */

    /* Complete the computation of the aux data */
    hss_finalize_aux_data( expanded_aux_data, size_hash, h,
                           private_key+PRIVATE_KEY_SEED(levels) );

    /* We have the root value; now format the public key */
    put_bigendian( public_key, levels, 4 );
    public_key += 4; len_public_key -= 4;
    put_bigendian( public_key, lm_type[0], 4 );
    public_key += 4; len_public_key -= 4;
    put_bigendian( public_key, lm_ots_type[0], 4 );
    public_key += 4; len_public_key -= 4;
    memcpy( public_key, I, I_LEN );
    public_key += I_LEN; len_public_key -= I_LEN;
    memcpy( public_key, root_hash, size_hash );
    public_key += size_hash; len_public_key -= size_hash;

    /* Hey, what do you know -- it all worked! */
    hss_zeroize( private_key, sizeof private_key ); /* Zeroize local copy of */
                                                   /* the private key */
    return true;
}

/*
 * The length of the private key
 */
size_t hss_get_private_key_len(unsigned levels,
                   const param_set_t *lm_type,
                   const param_set_t *lm_ots_type) {
       /* A private key is a 'public object'?  Yes, in the sense that we */
       /* export it outside this module */
    return PRIVATE_KEY_LEN(levels);
}
