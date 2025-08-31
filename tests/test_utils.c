#include "test_utils.h"

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "ahoi_defs.h"

void generate_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = rand() % 256;
    }
}

void ahoi_packets_assert_equal(ahoi_packet_t* p1, ahoi_packet_t* p2) {
    assert_non_null(p1);
    assert_non_null(p2);

    assert_int_equal(p1->src, p2->src);
    assert_int_equal(p1->dst, p2->dst);
    assert_int_equal(p1->type, p2->type);
    assert_int_equal(p1->flags, p2->flags);
    assert_int_equal(p1->seq, p2->seq);
    assert_int_equal(p1->pl_size, p2->pl_size);

    if (p1->pl_size > 0) {
        assert_non_null(p1->payload);
        assert_non_null(p2->payload);
        assert_memory_equal(p1->payload, p2->payload, p1->pl_size);
    }
}

size_t ahoi_serialize_rx(ahoi_packet_t* p, ahoi_footer_t* f, uint8_t* buf) {
    size_t f_size = sizeof(ahoi_footer_t);
    size_t resp = ahoi_serialize(p, buf);

    resp -= 2;

    // Abstract footer
    uint8_t* abs_footer = (uint8_t*) f;
    // Escape footer
    for (int i = 0; i < f_size; i++) {
        if (abs_footer[i] == 0x10) {
            buf[resp++] = 0x10;
        }
        buf[resp++] = abs_footer[i];
    }

    // Framing: DLE-ETX
    buf[resp++] = 0x10;
    buf[resp++] = 0x03;
    return resp;
}

void fill_serial_ack(int fd) {
    ahoi_packet_t ack = {
            .type = 0xFF
    };

    uint8_t msg[10] = {0};
    size_t len = ahoi_serialize(&ack, msg);
    write(fd, (void*) msg, len);
}

void fill_serial_nack(int fd) {
    ahoi_packet_t ack = {
            .type = 0xFE
    };

    uint8_t msg[10] = {0};
    size_t len = ahoi_serialize(&ack, msg);
    write(fd, (void*) msg, len);
}

void fill_cmd_resp(int fd, const ahoi_packet_t* const set_cmd) {
    ahoi_packet_t cmd_resp = {0};
    cmd_resp.type = set_cmd->type;
    cmd_resp.pl_size = set_cmd->pl_size;
    cmd_resp.payload = set_cmd->payload;

    uint8_t msg[16 + set_cmd->pl_size];
    size_t len = ahoi_serialize(&cmd_resp, msg);
    write(fd, (void*) msg, len);
}

void fill_ack_resp(int fd, const ahoi_packet_t* const data) {
    ahoi_packet_t ack = {0};
    ack.type = 127;
    ack.src = data->dst;
    ack.dst = data->src;

    ahoi_footer_t footer = {0};
    generate_random_bytes((uint8_t*) &footer, sizeof(ahoi_footer_t));

    uint8_t msg[2*(HEADER_SIZE + 15)];
    size_t len = ahoi_serialize_rx(&ack, &footer, msg);
    write(fd, (void*) msg, len);
}

void fill_rack_resp(int fd, const ahoi_packet_t* const data) {
    ahoi_packet_t rack = {0};
    rack.type = 127;
    rack.src = data->dst;
    rack.dst = data->src;
    rack.pl_size = 16;

    uint8_t payload[rack.pl_size];
    generate_random_bytes(payload, rack.pl_size);
    rack.payload = payload;

    ahoi_footer_t footer = {0};
    generate_random_bytes((uint8_t*) &footer, sizeof(ahoi_footer_t));

    uint8_t msg[2*(HEADER_SIZE + rack.pl_size + 15)];
    size_t len = ahoi_serialize_rx(&rack, &footer, msg);
    write(fd, (void*) msg, len);
}