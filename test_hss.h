#include <stdbool.h>

extern bool test_testvector(bool fast_flag, bool quiet_flag);
extern bool test_keygen(bool fast_flag, bool quiet_flag);
extern bool test_load(bool fast_flag, bool quiet_flag);
extern bool test_sign(bool fast_flag, bool quiet_flag);
extern bool test_sign_inc(bool fast_flag, bool quiet_flag);
extern bool test_stat(bool fast_flag, bool quiet_flag);
extern bool test_verify(bool fast_flag, bool quiet_flag);
extern bool test_verify_inc(bool fast_flag, bool quiet_flag);
extern bool test_key_load(bool fast_flag, bool quiet_flag);
extern bool test_reserve(bool fast_flag, bool quiet_flag);
extern bool test_thread(bool fast_flag, bool quiet_flag);
extern bool test_h25(bool fast_flag, bool quiet_flag);

extern bool check_threading_on(bool fast_flag);
extern bool check_h25(bool fast_flag);
