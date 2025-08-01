#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "common_defs.h"
#include "sender.h"
#include "core.h"
#include "security.h"
#include "receiver.h"

static uint8_t key[KEY_SIZE] = {0};

// Unit test using pipe()
static void send_ahoi_packet_test(void **state) {
    (void) state;

    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = 0x00;
    packet.pl_size = 3;

    uint8_t payload_data[100] = {0x11, 0x22, 0x10}; // 0x10 to test the escape
    packet.payload = payload_data;

    // Send
    packet_send_status status = send_ahoi_packet(pipefd[1], &packet);
    assert_int_equal(status, PACKET_SEND_OK);

    // Read
    uint8_t buffer[256] = {0};
    ssize_t read_len = read(pipefd[0], buffer, sizeof(buffer));
    assert_true(read_len > 0);

    // verify DLE-ETX
    assert_int_equal(buffer[0], 0x10);
    assert_int_equal(buffer[1], 0x02);

    // Verify DLE-ETX at the end
    assert_int_equal(buffer[read_len - 2], 0x10);
    assert_int_equal(buffer[read_len - 1], 0x03);

    close(pipefd[0]);
    close(pipefd[1]);
}

static void send_ahoi_packet_null_payload_test(void **state) {
    (void) state;

    ahoi_packet_t packet = {0};
    packet.payload = NULL;  // Intentionally invalid
    packet.pl_size = 4;

    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    packet_send_status status = send_ahoi_packet(pipefd[1], &packet);
    assert_int_equal(status, PACKET_SEND_KO);

    close(pipefd[0]);
    close(pipefd[1]);
}

static void secure_ahoi_packet_overflow_test(void **state) {
    (void) state;

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = 0x00;
    
    // Configuramos un tamaño de payload que causaría overflow al agregar el TAG
    packet.pl_size = MAX_SECURE_PAYLOAD_SIZE - TAG_SIZE + 1;  // Excede el límite

    // Asignamos exactamente el tamaño que dice pl_size (sin espacio extra para el TAG)
    uint8_t *tight_payload = malloc(packet.pl_size);
    assert_non_null(tight_payload);
    packet.payload = tight_payload;

    // Llamamos directamente a secure_ahoi_packet (no necesitamos send_ahoi_packet)
    secure_status status = secure_ahoi_packet(&packet);
    assert_int_equal(status, SECURE_KO);

    free(tight_payload);
}


static void test_decode_ahoi_packet_valid(void **state) {
    (void) state;

    // Initialize the key
    store_key(key);

    // Step 1: Create the payload
    const uint8_t test_payload[100] = {0x11, 0x22, 0x33, 0x44};
    const size_t payload_size = sizeof(test_payload);

    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[MAX_PACKET_SIZE];  // buffer enough 
    packet.payload = payload_buf;

    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x10;
    packet.flags = 0x01;
    packet.seq = 0;
    packet.pl_size = payload_size;

    memcpy(packet.payload, test_payload, payload_size);

    // Step 2: encrypt the payload
    secure_status sec_status = secure_ahoi_packet(&packet);
    assert_int_equal(sec_status, SECURE_OK);
    assert_true(packet.pl_size > TAG_SIZE);

    // Step 3: (HEADER + payload_encrypted + tag)
    const size_t total_len = HEADER_SIZE + packet.pl_size;
    uint8_t* serialized = malloc(total_len);
    assert_non_null(serialized);
    memcpy(serialized, &packet, HEADER_SIZE);
    memcpy(serialized + HEADER_SIZE, packet.payload, packet.pl_size);

    // Step 4: Decrpyt 
    ahoi_packet_t decoded = {0};
    decoded.payload = calloc(1, MAX_PACKET_SIZE);  // Enough space

    packet_decode_status dec_status = decode_ahoi_packet(serialized, total_len, &decoded);
    assert_int_equal(dec_status, PACKET_DECODE_OK);

    // Step 5: verify
    assert_int_equal(decoded.src, packet.src);
    assert_int_equal(decoded.dst, packet.dst);
    assert_int_equal(decoded.type, packet.type);
    assert_int_equal(decoded.flags, packet.flags);
    assert_int_equal(decoded.seq, packet.seq);
    assert_int_equal(decoded.pl_size, payload_size);
    assert_memory_equal(decoded.payload, test_payload, payload_size);

    // free the space
    free(serialized);
    free(decoded.payload);
}

static void decode_ahoi_packet_too_short_test(void **state) {
    (void)state;

    uint8_t short_data[HEADER_SIZE - 2] = {0};  // less than HEADER_SIZE
    ahoi_packet_t pkt = {0};
    pkt.payload = malloc(16); 
    assert_non_null(pkt.payload);

    packet_decode_status result = decode_ahoi_packet(short_data, sizeof(short_data), &pkt);
    assert_int_equal(result, PACKET_DECODE_KO);

    free(pkt.payload);
}

static void test_decode_ahoi_packet_invalid_tag(void **state) {
    (void) state;

    store_key(key);

    const uint8_t test_payload[100] = {0xAA, 0xBB, 0xCC, 0xDD};
    const size_t payload_size = sizeof(test_payload);

    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[MAX_PACKET_SIZE];
    packet.payload = payload_buf;

    packet.src = 0x03;
    packet.dst = 0x04;
    packet.type = 0x20;
    packet.flags = 0x01;
    packet.seq = 0;
    packet.pl_size = payload_size;

    memcpy(packet.payload, test_payload, payload_size);

    secure_status sec_status = secure_ahoi_packet(&packet);
    assert_int_equal(sec_status, SECURE_OK);

    const size_t total_len = HEADER_SIZE + packet.pl_size;
    uint8_t* serialized = malloc(total_len);
    assert_non_null(serialized);

    memcpy(serialized, &packet, HEADER_SIZE);
    memcpy(serialized + HEADER_SIZE, packet.payload, packet.pl_size);

    // Corrupt the last byte of tag
    serialized[total_len - 1] ^= 0xFF;

    ahoi_packet_t decoded = {0};
    decoded.payload = calloc(1, MAX_PACKET_SIZE);
    assert_non_null(decoded.payload);

    packet_decode_status dec_status = decode_ahoi_packet(serialized, total_len, &decoded);

    // Should fail
    assert_int_equal(dec_status, PACKET_DECODE_KO);

    free(serialized);
    free(decoded.payload);
}

static int callback_called = 0;

static void packet_callback(const ahoi_packet_t* pkt) {
    assert_non_null(pkt);
    assert_int_equal(pkt->src, 0x01);
    assert_int_equal(pkt->dst, 0x02);
    assert_int_equal(pkt->type, 0x20);
    assert_int_equal(pkt->flags, 0x00);
    assert_int_equal(pkt->pl_size, 4);
    const uint8_t expected_payload[100] = {0xAA, 0xBB, 0xCC, 0x10};
    assert_memory_equal(pkt->payload, expected_payload, 4);
    callback_called = 1;
}

static void receive_ahoi_packet_test(void **state) {
    (void) state;
    store_key(key);

    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    // Create the packet
    ahoi_packet_t packet = {0};
    static uint8_t payload_buf[64];
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.type = 0x20;
    packet.flags = 0x00;
    packet.seq = 0;
    packet.pl_size = 4;
    packet.payload = payload_buf;

    const uint8_t original_payload[100] = {0xAA, 0xBB, 0xCC, 0x10}; 
    memcpy(packet.payload, original_payload, 4);

   secure_status sec_status = secure_ahoi_packet(&packet);
    assert_int_equal(sec_status, SECURE_OK);

    // DLE-STX and DLE-ETX
    const size_t raw_size = HEADER_SIZE + packet.pl_size;
    uint8_t *raw_buf = malloc(raw_size);
    assert_non_null(raw_buf);
    memcpy(raw_buf, &packet, HEADER_SIZE);
    memcpy(raw_buf + HEADER_SIZE, packet.payload, packet.pl_size);

    // Simulate the sending with DLE-STX, DLE-ETX and escapes
    uint8_t framed[512];
    size_t framed_pos = 0;

    // DLE-STX
    framed[framed_pos++] = 0x10;
    framed[framed_pos++] = 0x02;

    for (size_t i = 0; i < raw_size; ++i) {
        if (raw_buf[i] == 0x10) {
            framed[framed_pos++] = 0x10;
        }
        framed[framed_pos++] = raw_buf[i];
    }

    // DLE-ETX
    framed[framed_pos++] = 0x10;
    framed[framed_pos++] = 0x03;

    free(raw_buf);

    // simulates the TX part
    ssize_t written = write(pipefd[1], framed, framed_pos);
    assert_true(written > 0);

    //Write the function 
    callback_called = 0;
    packet_rcv_status rcv_status = receive_ahoi_packet(pipefd[0], packet_callback, NULL, 1000);
    assert_int_equal(rcv_status, PACKET_RCV_OK);
    assert_int_equal(callback_called, 1);

    close(pipefd[0]);
    close(pipefd[1]);
}

static void receive_ahoi_packet_truncated_test(void **state) {
    (void) state;

    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    // Create the secuence incomplete
    uint8_t fake_packet[] = {
        0x10, 0x02,  // DLE-STX
        0x01, 0x02, 0x03, 0x04  // without DLE-ETX
    };

    // write pipe
    ssize_t written = write(pipefd[1], fake_packet, sizeof(fake_packet));
    assert_true(written > 0);

    // try to write
    packet_rcv_status rcv_status = receive_ahoi_packet(pipefd[0], packet_callback, NULL, 100);
    assert_true(rcv_status == PACKET_RCV_TIMEOUT || rcv_status == PACKET_RCV_KO);


    close(pipefd[0]);
    close(pipefd[1]);
}


static void receive_ahoi_packet_invalid_content_test(void **state) {
    (void) state;

    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    // DLE-STX + data short + DLE-ETX
    uint8_t invalid_packet[] = {
        0x10, 0x02,  // DLE-STX
        0x01, 0x02,  // too short
        0x10, 0x03   // DLE-ETX
    };

    // write pipe
    ssize_t written = write(pipefd[1], invalid_packet, sizeof(invalid_packet));
    assert_true(written > 0);

    // try to write
    packet_rcv_status rcv_status = receive_ahoi_packet(pipefd[0], packet_callback, NULL, 100);
    assert_int_equal(rcv_status, PACKET_RCV_KO);

    close(pipefd[0]);
    close(pipefd[1]);
}


// Cmocka main: define the test
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(send_ahoi_packet_test),
        cmocka_unit_test(send_ahoi_packet_null_payload_test),
        cmocka_unit_test(secure_ahoi_packet_overflow_test),
        cmocka_unit_test(test_decode_ahoi_packet_valid),
        cmocka_unit_test(decode_ahoi_packet_too_short_test),
        cmocka_unit_test(test_decode_ahoi_packet_invalid_tag),
        cmocka_unit_test(receive_ahoi_packet_test),
        cmocka_unit_test(receive_ahoi_packet_truncated_test),
        cmocka_unit_test(receive_ahoi_packet_invalid_content_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
