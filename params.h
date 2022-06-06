#ifndef PARAM_H
#define PARAM_H

#include "common_defs.h"


#define NIST_LEVEL 3

/*
 * I couldn't find security analysis to match NIST security levels anywhere
 * below are security assumptions, need to be revised in the future.
 */
#if NIST_LEVEL == 1
/*
+---------+------------+---------+-------------+
| ParmSet | KeyGenTime | SigSize | KeyLifetime |
+---------+------------+---------+-------------+
| 10/10   | -----      | ----    | ----------  |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H10
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#elif NIST_LEVEL == 3
/*
+---------+------------+---------+-------------+
| ParmSet | KeyGenTime | SigSize | KeyLifetime |
+---------+------------+---------+-------------+
| 15/10   | 6 sec      | 3172    | 9 hours     |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H15
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H10
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#elif NIST_LEVEL == 5
/*
+---------+------------+---------+-------------+
| ParmSet | KeyGenTime | SigSize | KeyLifetime |
+---------+------------+---------+-------------+
| 15/15   | 6 sec      | 3332    | 12 days     |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H15
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#else
#error "Unspecified NIST_LEVEL {1,3,5}"

#endif

#endif