#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "common_defs.h"
#include "security.h"

static void nonce_gen_test(void **state) {
    (void) state;

    uint8_t seq = 0;
    uint8_t nonce_buf[NONCE_SIZE] = {0};
    uint8_t nonce_buf2[NONCE_SIZE] = {0};

    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf, NONCE_SIZE));
    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf2, NONCE_SIZE));
    assert_memory_equal(nonce_buf, nonce_buf2, NONCE_SIZE);

    seq++;
    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf, NONCE_SIZE));
    assert_memory_not_equal(nonce_buf, nonce_buf2, NONCE_SIZE);
    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf2, NONCE_SIZE));
    assert_memory_equal(nonce_buf, nonce_buf2, NONCE_SIZE);
}

static void nonce_gen_neg_test(void **state) {
    (void) state;

    uint8_t seq = 0;
    uint8_t nonce_buf[NONCE_SIZE] = {0};
    uint8_t nonce_buf2[NONCE_SIZE] = {0};

    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf, NONCE_SIZE));

    seq++;
    assert_int_equal(NONCE_GEN_OK, generate_nonce(seq, nonce_buf2, NONCE_SIZE));
    assert_memory_not_equal(nonce_buf, nonce_buf2, NONCE_SIZE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(nonce_gen_test),
        cmocka_unit_test(nonce_gen_neg_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
