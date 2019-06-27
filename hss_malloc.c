/*
 * This is the instrumented malloc implementation; used for testing the
 * HSS code for malloc issues (memory leaks, resilence against malloc
 * failures, etc
 *
 * This is sort of electric-fence-light, however it's a lot easier in our
 * case:
 * - We won't have *that* many malloc's outstanding (hence a linked list
 *   is a reasonable database)
 * - The malloc's are free'd in mostly LIFO order (which a linked list really
 *   likes
 * - Even though we're multithreaded, only the main thread calls us (and
 *   so we can just ignore the issue)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hss.h"
#include "config.h"
#include "common_defs.h"
#include "hss_malloc.h"

#if TEST_INSTRUMENTATION

#include <stdio.h>

/*
 * We put one of these both before and after the user buffer; it is used
 * to detect potential overwrite/underwrites
 */
union fence {
    sequence_t align1;
    void *align2;
    double align3;
    void (*align4)(void);
    unsigned char buffer[1];
};

static union fence start_fence, end_fence;  /* These are the expected */
                       /* images we write before and after the buffer */

static unsigned char my_rand(void) {
    static uint_fast32_t n = 0;
    n += (n*n) | 5;
    return n >> 24;
}

static void set_random_fence_value( union fence *fence ) {
    size_t i;

    for (i=0; i<sizeof *fence; ) {
        unsigned char c = my_rand();
            /* Skip very small and large values; this is here to detect */
            /* overwrites; overwrite data is more likely to be very small */
            /* and large values */
        if (c < 10 || c > 250) continue;
        fence->buffer[i++] = c;
    }
}

struct malloc_chain {
    struct malloc_chain *next;
    size_t length;
    enum malloc_usage usage;
    union fence start_fence;
        /* We assume there is no padding here (which isn't, strictly */
        /* speaking, guarranteed by C99, however *any* same compiler will */
        /* do it).  In any case, if there is padding, that just means that */
        /* our underwrite checking is less effective */
    unsigned char buffer[1]; /* We give this buffer to the application */
    /* There's an end_fence at the end of the buffer (after length bytes) */
};

static struct malloc_chain *chain = 0;  /* The list of outstanding malloc's */


void *hss_malloc( size_t length, enum malloc_usage usage ) {
    if (length == 0) {
        /* While C99 allows mallocing 0 length buffers, the behavior */
        /* is implementation-defined; we error it out */
        fprintf( stderr, "Error: zero length malloc detected: usage = %d\n",
                                                                     usage );
        exit(EXIT_FAILURE);
    }

    /* The actual ammount we allocate */
    size_t real_length = sizeof (struct malloc_chain) +
                         length + sizeof(union fence);
    struct malloc_chain *p = malloc( real_length );
    if (p == 0) {
        /* The malloc we're using is supposed to have enough memory */
        fprintf( stderr, "Error: real malloc failure: "
                         "length = %u usage = %d\n", (unsigned)length, usage );
        exit(EXIT_FAILURE);
    }

    /* If we're doing a first malloc (or if we've free'ed everything, and */
    /* then malloc'ing), select random start_fence, end_fence values */
    if (chain == 0) {
        set_random_fence_value( &start_fence );
        set_random_fence_value( &end_fence );
    }

    /* Put the malloc on the chain */
    p->next = chain;
    chain = p;

    /* Fill in the malloc length and reason */
    p->length = length;
    p->usage = usage;

    /* Set the guard that goes in front of the data */
    p->start_fence = start_fence;

    /* Fill the buffer with random data; this will trip up the code if */
    /* it implicitly expects a zeroized buffer */
    size_t i;
    for (i=0; i<length; i++) {
        p->buffer[i] = my_rand();
    }

    /* Fill in the end fence */
    memcpy( &p->buffer[i], &end_fence, sizeof end_fence );

    
    return p->buffer;
}

void hss_free(void *buffer) {
    if (buffer == 0) return;  /* free(NULL) does nothing */

    struct malloc_chain **p, *q = 0;
    /*
     * Search for the buffer on the chain
     */
    for (p = &chain; *p; p = &(*p)->next ) {
        q = *p;

        if (q->buffer == buffer) {
            /* Found it! */
            break;
        }
    }

    if (!*p) {
        fprintf( stderr, "Error: attempt to free unallocated buffer\n" );
        exit(EXIT_FAILURE);
    }

    /* Check the fences to see if they're still intact */
    if (0 != memcmp( &q->start_fence, &start_fence, sizeof start_fence )) {
        fprintf( stderr, "Error: buffer underwrite detected: usage = %d\n",
                          q->usage );
        exit(EXIT_FAILURE);
    }
    size_t length = q->length;
    if (0 != memcmp( &q->buffer[ length ], &end_fence, sizeof end_fence )) {
        fprintf( stderr, "Error: buffer overwrite detected: usage = %d\n",
                          q->usage );
        exit(EXIT_FAILURE);
    }

    /* Optionally, we could scan the buffer for potential secrets */

    /* Scrub the buffer (so that if the code tries to access it again, */
    /* it'll get random data) */
    size_t i;
    for (i=0; i<length; i++) {
        q->buffer[ i ] = my_rand();
    }

    /* Everything looks good; remove the element from the chain */
    *p = q->next;
    free(q);
}

/*
 * Report if we've seen any leaks
 */
bool hss_report_memory_leak(void) {
    if (!chain) {
        printf( "No memory leaks detected\n" );  /* Hurray! */
        return true;
    }
    printf( "Memory leaks detected:\n" );  /* Grumble... */
    int i;
    struct malloc_chain *p;
        /* Summarize what we've seen */
    for (p = chain, i = 0; p && i < 20; p = p->next, i++) {
        printf( " Buffer usage %d: length %u\n", p->usage,
                                                (unsigned)p->length );
    }
    if (p) {
        printf( " And more not listed...\n" );
    }
    return false;
}

#else
/*
 * Instrumentation is turned off; don't report about any memory leaks
 * (as we haven't been tracking it)
 */
bool hss_report_memory_leak(void) {
    return true;
}
#endif
