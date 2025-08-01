#ifndef AHOI_LIB_COM_H
#define AHOI_LIB_COM_H

#include <sys/time.h>

#include "core.h"

#define RECV_BUF_SIZE 512

typedef enum {
    PACKET_SEND_OK,
    PACKET_SEND_KO
} packet_send_status;

typedef enum {
    PACKET_RCV_OK,
    PACKET_RCV_TIMEOUT,
    PACKET_RCV_KO
} packet_rcv_status;

typedef struct {
    struct timeval begin;
    struct timeval end;
} timing_t;

int open_serial_port(const uint8_t *port, int baudrate);

void set_timing_cb(void (*cb)(const timing_t*));

packet_send_status send_ahoi_cmd(int fd, const ahoi_packet_t* ahoi_packet, uint8_t* rsp_buf, size_t buf_len, size_t* rsp_len);

packet_send_status send_ahoi_data(int fd, ahoi_packet_t* ahoi_packet);

packet_rcv_status receive_ahoi_packet_sync(int fd, ahoi_packet_t* p, int timeout_ms);

#endif // AHOI_LIB_COM_H
