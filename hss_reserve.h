#if !defined( HSS_RESERVE_H_ )
#define HSS_RESERVE_H_

/*
 * This is the internal include file for the reservation functions for this
 * subsystem. It should not be used by applications
 */

#include "common_defs.h"

struct hss_working_key;

void hss_set_reserve_count(struct hss_working_key *w, sequence_t count);

bool hss_check_end_key(struct hss_working_key *w, sequence_t new_count,
        struct hss_extra_info *info, bool *trash_private_key);

bool hss_advance_count(struct hss_working_key *w, sequence_t new_count,
        struct hss_extra_info *info, int num_sigs_updated);

#endif /* HSS_RESERVE_H_ */
