#if !defined( HSS_MALLOC_H_ )
#define HSS_MALLOC_H_

#include <stdlib.h>

#if TEST_INSTRUMENTATION

/* These are the various reasons we malloc things */
enum malloc_usage {
    mu_working_key = 1,
    mu_signed_pk,
    mu_stack,
    mu_tree,
    mu_subtree,
    mu_suborder,
    mu_thread_collection,
    mu_work_item,
    mu_max                /* Last item */
};

/*
 * Our special instrumented malloc/free routines
 */
void *hss_malloc( size_t length, enum malloc_usage usage );
void  hss_free( void *buffer );

#else

/*
 * Instrumentation is turned off; go directly to the C library with malloc
 * and free requests
 */
#define hss_malloc(length, usage)  malloc(length)
#define hss_free(buffer)           free(buffer)

#endif

#endif /* HSS_MALLOC_H_ */
