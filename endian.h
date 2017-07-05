#include <stddef.h>

void put_bigendian( void *target, unsigned long long value, size_t bytes );
unsigned long long get_bigendian( const void *target, size_t bytes );
