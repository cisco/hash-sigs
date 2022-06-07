#ifndef PARAM_H
#define PARAM_H

#include "common_defs.h"

#define NIST_LEVEL 2
#define DEBUG 0

#define LMS_PUBLICKEYBYTES 60
#define LMS_SECRETKEYBYTES 64

#define LMS_H10W8_BYTES 1566
#define LMS_H15W8_BYTES 1616
#define LMS_H20W8_BYTES 1776

#define LMS_H10H10W8_BYTES 2964
#define LMS_H10H15W8_BYTES 3124
#define LMS_H15H10W8_BYTES 3124

#define LMS_H15H15W8_BYTES 3284

#define CRYPTO_PUBLIC_KEY LMS_PUBLICKEYBYTES
#define CRYPTO_SECRET_KEY LMS_SECRETKEYBYTES

/*
 * I couldn't find security analysis to match NIST security levels anywhere
 * below are security assumptions, need to be revised in the future.
 */
#if NIST_LEVEL == 1
/*
+--------------+------------+---------+-------------+-------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Times |
+--------------+------------+---------+-------------+-------+
| 10, w=4      | (60, 64)   | 2512    | 2^10 - 1    |       |
| 15, w=4      | (60, 64)   | 2672    | 2^15 - 1    |       |
| 10, w=8      | (60, 64)   | 1566    | 2^10 - 1    | 1.95  |
| 15, w=8      | (60, 64)   | 1616    | 2^15 - 1    | 36.3  |
*/
#define PARAM_LEVEL 1
#define PARAM_LM_HEIGHT LMS_SHA256_N32_H15
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define CRYPTO_BYTES LMS_H15W8_BYTES

#elif NIST_LEVEL == 2
/*
+--------------+------------+---------+-------------+-------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Times |
+--------------+------------+---------+-------------+-------+
| 10/15, w=4   | (60, 64)   | 5236    | 2^25 - 1    |       |
| 15/10, w=4   | (60, 64)   | 5236    | 2^25 - 1    |       |
| 5/15 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 24.3  |
| 10/10, w=8   | (60, 64)   | 2964    | 2^20 - 1    | 1.9   |
| 15/5 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 40.2  |
| 10/15, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 25.5  |
| 15/10, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 41.0  |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H10
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define CRYPTO_BYTES LMS_H10H10W8_BYTES

#elif NIST_LEVEL == 3
/*
+--------------+------------+---------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures |
+--------------+------------+---------+-------------+
| 15/15, w=8   | (60, 64)   | 3284    | 2^30 -1     |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H15
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define CRYPTO_BYTES LMS_H15H15W8_BYTES

#else
#error "Unspecified NIST_LEVEL {1,2,3}"

#endif

#endif