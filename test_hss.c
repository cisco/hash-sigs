/*
 * This is the test harness for the LMS implementation
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "test_hss.h"

/*
 * This is the list of tests we know about
 */
static struct {
    const char *keyword;               /* The name of this test */
    bool (*test_routine)(bool, bool);  /* How to run this test */
    const char *test_name;             /* Extended description */
    bool warn_expense;                 /* Should we warn that this test */
                                       /* will take a while in -full mode */
    bool (*test_enabled)(bool);        /* Check if this tests is enabled */
} test_list[] = {
    { "testvector", test_testvector, "test vector from the draft", false },
    { "keygen", test_keygen, "key generation function test", false },
    { "load", test_load, "key load test", false },
    { "sign", test_sign, "signature test", false },
    { "signinc", test_sign_inc, "incremental signature test", true },
    { "stat", test_stat, "statistical test", false },
    { "keyload", test_key_load, "key loading test", true },
    { "verify", test_verify, "signature verification test", true },
    { "verifyinc", test_verify_inc, "incremental verification test",
        false },
    { "reserve", test_reserve, "reservation test", false },
    { "thread", test_thread, "threading logic test", false,
        check_threading_on },
    { "h25", test_h25, "H=25 test", true, check_h25 },
 /* Add more here */  
};

/*
 * This will run the listed tests; tests is a bitmap containing which tests
 * should be run; tests&1 is test_lis[t0], tests&2 is test_list[1], etc
 */
static int run_tests( unsigned tests, bool force_tests, bool fast_flag, bool quiet_flag ) {
    int success_flag = EXIT_SUCCESS;
    int i;
    for (i = 0; i < sizeof test_list / sizeof *test_list; i++) {
        if (0 == ( tests & (1<<i))) continue;
        printf( "Running %s", test_list[i].test_name );
        if (test_list[i].warn_expense && !fast_flag) {
            printf( " (warning: this will take a while)" );
        }
        printf( ":\n" );
        fflush(stdout);
        if (test_list[i].test_enabled &&
                                   !test_list[i].test_enabled(fast_flag)) {
            continue;
        }
        bool test_passed = test_list[i].test_routine(fast_flag, quiet_flag);
        if (test_passed) {
            printf( "  Passed        \n" );
        } else {
            printf( "  **** TEST FAILED ****\n" );
            success_flag = EXIT_FAILURE;
            if (!force_tests) break;   /* Stop on first failure? */
        }
    }
    return success_flag;
}

static void usage(char *program_name) {
    printf( "Usage: %s [-f] [-q] [-full] [tests]\n", program_name );
    printf( "   \"all\" will run all tests\n" );
    printf( "   -q will remove progress messages during the longer tests\n" );
    printf( "   -f will force running of all tests, even on failure\n" );
    printf( "   -full will have the tests run the entire suite\n" );
    printf( "          Warning: some tests may take over an hour in full mode\n" );
    printf( "Supported tests:\n" );
    int i;
    for (i = 0; i < sizeof test_list / sizeof *test_list; i++) {
        printf( "    \"%s\": %s\n", test_list[i].keyword, test_list[i].test_name );
    }
}

int main( int argc, char **argv ) {
    int i;
    unsigned tests_to_run = 0;
    bool force_tests = false;
    bool fast_flag = true;
    bool quiet_flag = false;
    for (i = 1; i < argc; i++) {
        char *test = argv[i];
        bool found_test = false;
        int j;
        for (j = 0; j < sizeof test_list / sizeof *test_list; j++) {
            if (0 == strcmp( test, test_list[j].keyword)) {
                tests_to_run |= (1<<j);
                found_test = true;
                break;
            }
        }
        if (found_test) continue;

        /* Not any of the standard tests; check to see if it's an adverb */ 
        if (0 == strcmp( test, "all" )) {
            tests_to_run = ~0;    /* All of them */
        } else if (0 == strcmp( test, "-f" )) {
            force_tests = true;
        } else if (0 == strcmp( test, "-full" )) {
            fast_flag = false;
        } else if (0 == strcmp( test, "-q" )) {
            quiet_flag = true;
        } else {
            printf( "Unrecognized test %s\n", test );
            usage( argv[0] );
            return EXIT_FAILURE;
        }
    }
    if (tests_to_run == 0) {
        usage( argv[0] );
        exit(EXIT_FAILURE);  /* FAILURE == We didn't pass the tests */
    }

    return run_tests( tests_to_run, force_tests, fast_flag, quiet_flag );
}
