#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ahoi_defs.h"
#include "com.h"
#include "core.h"

#include "test_utils.h"

static uint8_t key[KEY_SIZE] = {0};
static uint8_t g_payload_buffer[MAX_PAYLOAD_SIZE] = {0};
static ahoi_packet_t g_packet = {
    .payload = g_payload_buffer
};
static ahoi_footer_t g_footer = {0};

static int sv[2];
int setup_socketpair(void **state) {
    (void) state;

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    return 0;
}

int teardown_socketpair(void **state) {
    (void) state;

    close(sv[0]);
    close(sv[1]);

    return 0;
}

static void send_ahoi_packet_test(void **state) {
    (void) state;

    fill_serial_ack(sv[1]);

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = 0x00;
    packet.pl_size = 3;

    uint8_t payload_data[100] = {0x11, 0x22, 0x10};
    packet.payload = payload_data;

    // Send
    packet_send_status status = send_ahoi_data(sv[0], &packet);
    assert_int_equal(status, PACKET_SEND_OK);
}

static void send_ahoi_packet_null_payload_test(void **state) {
    (void) state;

    ahoi_packet_t packet = {0};
    packet.payload = NULL;  // Intentionally invalid
    packet.pl_size = 4;

    packet_send_status status = send_ahoi_data(sv[0], &packet);
    assert_int_equal(status, PACKET_SEND_KO);
}

static void send_ahoi_packet_null_packet_test(void **state) {
    (void) state;

    packet_send_status status = send_ahoi_data(sv[0], NULL);
    assert_int_equal(status, PACKET_SEND_KO);
}

static void send_ahoi_set_cmd_test(void **state) {
    (void) state;

    uint8_t id = 0x15;

    ahoi_packet_t cmd = {0};
    cmd.type = AHOI_ID_CMD;
    cmd.pl_size = 1;
    cmd.payload = &id;

    fill_cmd_resp(sv[1], &cmd);
    uint8_t resp_buf[100] = {0};
    size_t resp_len = 0;

    // Send
    packet_send_status status = send_ahoi_cmd(sv[0], &cmd, resp_buf, sizeof(resp_buf), &resp_len);
    assert_int_equal(status, PACKET_SEND_OK);
    assert_int_equal(1, resp_len);
    assert_int_equal(id, resp_buf[0]);
}

static void send_ahoi_cmd_nack_test(void **state) {
    (void) state;

    uint8_t id = 0x15;

    ahoi_packet_t cmd = {0};
    cmd.type = AHOI_ID_CMD;
    cmd.pl_size = 1;
    cmd.payload = &id;

    fill_serial_nack(sv[1]);
    uint8_t resp_buf[100] = {0};
    size_t resp_len = 0;

    packet_send_status status = send_ahoi_cmd(sv[0], &cmd, resp_buf, sizeof(resp_buf), &resp_len);
    assert_int_equal(status, PACKET_SEND_KO);
}

static void recv_ahoi_ack(void **state) {
    (void) state;

    fill_serial_ack(sv[1]);

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = A_FLAG;
    packet.pl_size = 3;

    assert_int_equal(0x01, packet.flags);

    uint8_t payload_data[100] = {0x11, 0x22, 0x10};
    packet.payload = payload_data;

    fill_ack_resp(sv[1], &packet);

    // Send
    packet_send_status status = send_ahoi_data(sv[0], &packet);
    assert_int_equal(status, PACKET_SEND_OK);

    // Receive ack
    packet_rcv_status recv_status = receive_ahoi_packet_sync(sv[0], &g_packet, &g_footer, 100);
    assert_int_equal(recv_status, PACKET_RCV_OK);
    assert_true(is_ack(&g_packet));
    assert_int_equal(packet.src, g_packet.dst);
    assert_int_equal(packet.dst, g_packet.src);
    assert_int_equal(0, g_packet.pl_size);
}

static void recv_ahoi_rack(void **state) {
    (void) state;

    fill_serial_ack(sv[1]);

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = R_FLAG;
    packet.pl_size = 3;

    assert_int_equal(0x02, packet.flags);

    uint8_t payload_data[100] = {0x11, 0x22, 0x10};
    packet.payload = payload_data;

    fill_rack_resp(sv[1], &packet);

    // Send
    packet_send_status status = send_ahoi_data(sv[0], &packet);
    assert_int_equal(status, PACKET_SEND_OK);

    // Receive ack
    packet_rcv_status recv_status = receive_ahoi_packet_sync(sv[0], &g_packet, &g_footer, 100);
    assert_int_equal(recv_status, PACKET_RCV_OK);
    assert_true(is_ack(&g_packet));
    assert_int_equal(packet.src, g_packet.dst);
    assert_int_equal(packet.dst, g_packet.src);
    assert_true(g_packet.pl_size > 4);
}

static void recv_test(void **state) {
    (void) state;

//    fill_serial_ack(sv[1]);

    ahoi_packet_t packet = {0};
    packet.src = 0x01;
    packet.dst = 0x02;
    packet.flags = 0x00;
    packet.pl_size = 3;

    ahoi_footer_t f = {0};

    uint8_t payload_data[100] = {0x11, 0x22, 0x10};
    packet.payload = payload_data;

    uint8_t buff[1024] = {0};
    size_t to_write = ahoi_serialize_rx(&packet, &f, buff);

    size_t res = write(sv[0], buff, to_write);
    assert_int_equal(to_write, res);

    // Receive message
    packet_rcv_status msg_recv_status = receive_ahoi_packet_sync(sv[1], &g_packet, &g_footer, 100);
    assert_int_equal(msg_recv_status, PACKET_RCV_OK);
    assert_true(is_data_packet(&g_packet));

    ahoi_packets_assert_equal(&packet, &g_packet);
    assert_memory_equal(&f, &g_footer, FOOTER_SIZE);
}

int main(void) {
    const struct CMUnitTest send_tests[] = {
        cmocka_unit_test(send_ahoi_packet_test),
        cmocka_unit_test(send_ahoi_packet_null_payload_test),
        cmocka_unit_test(send_ahoi_packet_null_packet_test),
        cmocka_unit_test(send_ahoi_set_cmd_test),
        cmocka_unit_test(send_ahoi_cmd_nack_test),
        cmocka_unit_test(recv_ahoi_ack),
        cmocka_unit_test(recv_ahoi_rack),
    };

    const struct CMUnitTest recv_tests[] = {
            cmocka_unit_test(recv_test),
    };

    int res = cmocka_run_group_tests(send_tests, setup_socketpair, teardown_socketpair);
    res |= cmocka_run_group_tests(recv_tests, setup_socketpair, teardown_socketpair);
    return res;
}
