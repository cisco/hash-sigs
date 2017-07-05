#include <stdlib.h>

/* Zeroize an area, that is, scrub it from holding any potentially secret */
/* information */
void hss_zeroize( void *area, size_t len );
