#include <string.h>
#include "hash.h"
#include "sha256.h"
#include "hss_zeroize.h"
#include "config.h"

/*
 * This is the file that implements the hashing APIs we use internally.
 * At the present, our parameter sets support only one hash function
 * (SHA-256, using full 256 bit output), however, that is likely to change
 * in the future
 */

#if ALLOW_VERBOSE
#include <stdio.h>
#include <stdbool.h>
/*
 * Debugging flag; if this is set, we chat about what we're hashing, and what
 * the result is it's useful when debugging; however we probably don't want to
 * do this if we're multithreaded...
 */
bool hss_verbose = false;
#endif

#if TEST_INSTRUMENTATION
#include "hss_fault.h"

/*
 * These globals are the way we communicate with the fault testing logic
 * (test_fault.c); when it decides that it wants to inject a fault, that
 * code sets these globals, and we then inject a fault accordingly
 */
int hash_fault_enabled = 0;   /* Is hash fault injected enabled? */
                       /* 0 -> no */
                       /* 1 -> yes for the specific hash listed below */
                       /* 2 -> always */
int hash_fault_level;  /* Where we inject the fault; which LMS level */
                       /* in the HSS hierarchy are we attempting to */
                       /* target; 0 -> root LMS tree */
int hash_fault_reason; /* Where we inject the fault; which reason */
                       /* we perform the hash are we attempting to */
                       /* fault */
long hash_fault_count; /* Decrements when we get a match on both level */
                       /* and reason. When this count hits zero, we fault */

static int current_level; /* The LMS level that the code has told us that */
                       /* we're computing at */
void hss_set_level(int level) {
    if (hash_fault_enabled) {
        current_level = level;
    }
}

static enum hash_reason current_reason; /* The reason that the code told us */
                        /* that we're computing the next hash */
void hss_set_hash_reason(enum hash_reason reason) {
    if (hash_fault_enabled) {
        current_reason = reason;
    }
}

/*
 * This checks whether it's time to miscompute a hash
 */
static bool do_fault(void) {
    switch (hash_fault_enabled) {
    default:
        return false;
    case 1:
        if (current_level == hash_fault_level &&
                              current_reason == hash_fault_reason) {
            hash_fault_count -= 1;
            return hash_fault_count == 0;
        }
        return false;
    case 2:
        return true;
    }
}
#endif

/*
 * This will hash the message, given the hash type. It assumes that the result
 * buffer is large enough for the hash
 */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i< message_len; i++) printf( " %02x%s", ((unsigned char*)message)[i], (i%16 == 15) ? "\n" : "" );
    }
#endif

    switch (hash_type) {
    case HASH_SHA256: {
        SHA256_Init(&ctx->sha256);
#if TEST_INSTRUMENTATION
        if (do_fault()) {
            SHA256_Update(&ctx->sha256, "", 1); /* Miscompute the hash */
        }
#endif
        SHA256_Update(&ctx->sha256, message, message_len);
        SHA256_Final(result, &ctx->sha256);
#if ALLOW_VERBOSE
        if (hss_verbose) {
            printf( " ->" );
            int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char *)result)[i] ); printf( "\n" );
        }
#endif
        break;
    }
    }
}

void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len) {
    union hash_context ctx;
    hss_hash_ctx(result, hash_type, &ctx, message, message_len);
    hss_zeroize(&ctx, sizeof ctx);
}


/*
 * This provides an API to do incremental hashing.  We use it when hashing the
 * message; since we don't know how long it could be, we don't want to
 * allocate a buffer that's long enough for that, plus the decoration we add
 */
void hss_init_hash_context(int h, union hash_context *ctx) {
    switch (h) {
    case HASH_SHA256:
        SHA256_Init( &ctx->sha256 );
#if TEST_INSTRUMENTATION
        if (do_fault()) {
            SHA256_Update(&ctx->sha256, "", 1); /* Miscompute the hash */
        }
#endif
        break;
    }
}

void hss_update_hash_context(int h, union hash_context *ctx,
                         const void *msg, size_t len_msg) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i<len_msg; i++) printf( " %02x", ((unsigned char*)msg)[i] );
    }
#endif
    switch (h) {
    case HASH_SHA256:
        SHA256_Update(&ctx->sha256, msg, len_msg);
        break;
    }
}

void hss_finalize_hash_context(int h, union hash_context *ctx, void *buffer) {
    switch (h) {
    case HASH_SHA256:
        SHA256_Final(buffer, &ctx->sha256);
#if ALLOW_VERBOSE
    if (hss_verbose) {
        printf( " -->" );
        int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char*)buffer)[i] );
        printf( "\n" );
    }
#endif
        break;
    }
}


unsigned hss_hash_length(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 32;
    }
    return 0;
}

unsigned hss_hash_blocksize(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 64;
    }
    return 0;
}

