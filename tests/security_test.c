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

static uint8_t key[KEY_SIZE] = {0};

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

static void secure_ahoi_packet_oversized_payload_test(void **state) {
    (void)state;
    
    uint8_t large_payload[MAX_SECURE_PAYLOAD_SIZE + 1];
    ahoi_packet_t packet = {
        .payload = large_payload,
        .pl_size = MAX_SECURE_PAYLOAD_SIZE + 1  // Invalid Size
    };
    
    assert_int_equal(SECURE_KO, secure_ahoi_packet(&packet));
}

static void verify_packet_test(void **state) {
    (void) state;

    store_key(key);
    const uint8_t test_payload[] = {0x11, 0x22, 0x33, 0x44};
    const size_t payload_size = sizeof(test_payload);

    //Step 1 created and test
    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[50];
    packet.payload = payload_buf;
    assert_non_null(packet.payload);

    //header with values
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x10;
    packet.flags = 0x01;
    packet.seq = 0;
    packet.pl_size = payload_size;

    memcpy(packet.payload, test_payload, payload_size);
    

    // Encrypting the packet
    secure_status sec_result = secure_ahoi_packet(&packet);
    assert_int_equal(sec_result, SECURE_OK);
    assert_int_equal(packet.pl_size, payload_size + TAG_SIZE); // to test de size

    // verify test
    verify_status ver_result = verify_packet(&packet);
    assert_int_equal(ver_result, VERIFY_OK);
    
    assert_int_equal(packet.pl_size, payload_size);
    assert_memory_equal(packet.payload, test_payload, payload_size);
}

static void verify_packet_invalid_tag_test(void **state) {
    (void)state;

    store_key(key);
    const uint8_t test_payload[] = {0x11, 0x22, 0x33, 0x44};
    const size_t payload_size = sizeof(test_payload);

    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[50];
    packet.payload = payload_buf;
    
    // Header
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x10;
    packet.flags = 0x01;
    packet.seq = 0;
    packet.pl_size = payload_size;
    memcpy(packet.payload, test_payload, payload_size);

    // Encrypt
    secure_status sec_result = secure_ahoi_packet(&packet);
    assert_int_equal(sec_result, SECURE_OK);

    // it will change the last byte 
    packet.payload[packet.pl_size - 1] ^= 0xFF; // XOR for invert the order

    // Verify it will fail
    verify_status ver_result = verify_packet(&packet);
    assert_int_equal(ver_result, VERIFY_KO);
}

static void verify_packet_oversized_payload_test(void **state) {
    (void)state;

    store_key(key);
    
    // Create the packet 
    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[MAX_SECURE_PAYLOAD_SIZE + TAG_SIZE + 1];
    packet.payload = payload_buf;
    
    // The header with the wrong size
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x10;
    packet.flags = 0x01;
    packet.seq = 0;
    packet.pl_size = MAX_SECURE_PAYLOAD_SIZE + 1; // Invalide size

    // it will fail for the size
    verify_status ver_result = verify_packet(&packet);
    assert_int_equal(ver_result, VERIFY_KO);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(nonce_gen_test),
        cmocka_unit_test(nonce_gen_neg_test),
        cmocka_unit_test(secure_ahoi_packet_test),
        cmocka_unit_test(secure_ahoi_packet_null_payload_test),
        cmocka_unit_test(secure_ahoi_packet_oversized_payload_test),
        cmocka_unit_test(verify_packet_test),
        cmocka_unit_test(verify_packet_invalid_tag_test),
        cmocka_unit_test(verify_packet_oversized_payload_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}