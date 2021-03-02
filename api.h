/*
 * api.h
 *
 *  Created on: Jan 28, 2021
 *      Author: vader
 */

#ifndef API_H_
#define API_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "hss_internal.h"
#include "hss.h"
#include "hss_verify_inc.h"
#include "hss_sign_inc.h"
#include "hash.h"
#include "hss_zeroize.h"

//const char *default_parm_set = "5/4,5/4";

int keygen(unsigned char *sk, unsigned char *pk);

int sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
		unsigned long long mlen, unsigned char *private_key);

int verify(unsigned char *pk, unsigned char *sig, size_t sig_len,
		unsigned char *m, size_t mlen);

#endif /* API_H_ */
