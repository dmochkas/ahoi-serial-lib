#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

static void secure_ahoi_packet_test(void **state) {
    (void) state;

    // simulate data to test
    const uint8_t test_payload[] = {0x11, 0x22, 0x33, 0x44};
    const size_t payload_size = sizeof(test_payload);
    
    ahoi_packet_t packet = {0};
    packet.payload = malloc(payload_size + TAG_SIZE);
    memcpy(packet.payload, test_payload, payload_size);
    packet.pl_size = payload_size;

    secure_status result = secure_ahoi_packet(&packet);
    assert_int_equal(result, SECURE_OK);

    // Verify if the tag was added
    assert_memory_not_equal(packet.payload + payload_size, (uint8_t[TAG_SIZE]){0}, TAG_SIZE);

    //Verify the payload
    assert_memory_not_equal(packet.payload, test_payload, payload_size);
    free(packet.payload); 
}

static void secure_ahoi_packet_null_payload_test(void **state) {
    (void) state;

    ahoi_packet_t packet = {0};
    packet.payload = NULL;  // intentionally invalid
    packet.pl_size = 4;

    secure_status result = secure_ahoi_packet(&packet);
    assert_int_equal(result, SECURE_KO);  // the function has to fail
}

static void verify_packet_test(void **state) {
    (void) state;

    const uint8_t test_payload[] = {0x11, 0x22, 0x33, 0x44};
    const size_t payload_size = sizeof(test_payload);

    //Step 1 created and test
    ahoi_packet_t packet = {0};
    //packet.payload = malloc(payload_size + TAG_SIZE);
    packet.payload = malloc(payload_size + TAG_SIZE); // Extra size
    assert_non_null(packet.payload);

    //header with values
    packet.type = 1;  
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x10;
   // packet.status = 0x00;
    packet.pl_size = payload_size;

    memset(packet.payload, 0, payload_size + TAG_SIZE);
    memcpy(packet.payload, test_payload, payload_size);
    

    // Encrypting the packet
    secure_status sec_result = secure_ahoi_packet(&packet);
    assert_int_equal(sec_result, SECURE_OK);

    //assert_int_equal(packet.pl_size, payload_size + TAG_SIZE); // to test de size

    
    
    //verify_status ver_result = verify_packet(&packet);
    //assert_int_equal(ver_result, VERIFY_OK);

    
    //assert_int_equal(packet.pl_size, payload_size);
    //assert_memory_equal(packet.payload, test_payload, payload_size);

    free(packet.payload);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(nonce_gen_test),
        cmocka_unit_test(nonce_gen_neg_test),
        cmocka_unit_test(secure_ahoi_packet_test),
        cmocka_unit_test(secure_ahoi_packet_null_payload_test),
        cmocka_unit_test(verify_packet_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}